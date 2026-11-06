//! The core: directory ownership, the commit pipeline, recovery, the catalog.
//!
//! [`Core`] knows engines only through the contract in [`crate::engine`]:
//! the database facade hands it a [`Registry`] of the engines it hosts, and
//! a commit's staged work as `&dyn Staged`. Nothing here names an engine, so
//! a new engine needs no change in this file.
//!
//! # Group commit
//!
//! A commit runs in three parts:
//!
//! 1. Under the sequencer lock (short, no I/O): check the queue bound,
//!    validate against concurrent commits, take the next sequence number,
//!    encode the record, reserve the written keys, and queue the record.
//! 2. The writer: a commit that finds no writer at work becomes it, takes
//!    every queued record, appends them in sequence order, and syncs once.
//!    Commits queued meanwhile go in the next batch, so under load one sync
//!    serves many commits, and a lone commit is written and synced at once
//!    with no added wait. Writing outside the sequencer lock matters on
//!    Windows, where a write to the log waits for a sync in progress.
//! 3. In sequence order: apply the record from its encoded bytes, then make
//!    it visible. A commit waits here for the one before it.
//!
//! A failed append, sync, or apply halts the database: every commit not yet
//! durable or not yet applied fails with `Error::Storage`, and no later
//! commit is accepted. A failed sync is never retried, because the bytes may already
//! be gone from the cache; recovery after a restart decides what is durable.
//!
//! A priority-class commit needs nothing extra here: a batch is written as
//! soon as no other batch is being written, so no commit waits for a window
//! to fill.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use super::{
    catalog::{Catalog, CatalogStaged, Collection, MAX_NAME},
    fs::{self, DirLock},
    log::{CommitLog, MAX_RECORD},
    record::{self, Class, Kind, RecordView, RecordWriter, Seq},
};
use crate::{
    engine::{Engine, EngineId, Registry, Staged},
    error::{Error, Result},
};

/// Times a commit closure runs before [`Error::Conflict`].
pub(crate) const ATTEMPTS: usize = 4;

/// Commits between taking a sequence number and becoming visible, before a
/// new commit is refused with `Error::Busy`. Bounds the memory held by
/// encoded records waiting for their turn.
const MAX_IN_FLIGHT: usize = 4096;

/// Records waiting for the writer, and how far the log is durable.
#[derive(Debug, Default)]
struct Group {
    /// Encoded records in sequence order, not yet appended.
    pending: Vec<(Seq, Arc<[u8]>)>,
    /// A commit is appending and syncing a batch.
    writing: bool,
    /// Every record up to this sequence number is on stable storage.
    durable: Seq,
}

/// The sequencer's state, behind the sequencer lock.
#[derive(Debug, Default)]
struct CommitState {
    /// The last sequence number appended to the log.
    last: Seq,
    /// Commits appended and not yet visible (or failed).
    in_flight: usize,
}

/// Why one commit attempt did not land.
#[derive(Debug)]
pub(crate) enum Attempt {
    /// A concurrent commit wrote a key this one writes; run the closure
    /// again.
    Conflict,
    /// Anything else; returned to the caller.
    Failed(Error),
}

impl From<Error> for Attempt {
    fn from(err: Error) -> Self {
        Attempt::Failed(err)
    }
}

/// The core of one open database.
#[derive(Debug)]
pub(crate) struct Core {
    dir: PathBuf,
    log: CommitLog,
    commit: Mutex<CommitState>,
    /// The writer's queue. Taken after `commit` when both are held.
    group: Mutex<Group>,
    /// Woken when a batch is durable or the database halts.
    written: Condvar,
    /// The last applied sequence number; commits apply in turn behind it.
    applied: Mutex<Seq>,
    /// Woken when `applied` moves or the database halts.
    turn: Condvar,
    /// The highest sequence number applied in every engine it touched.
    visible: AtomicU64,
    /// Set after a failed log write or apply: no further commits.
    halted: AtomicBool,
    /// Snapshots of running transactions, with their counts.
    snapshots: Mutex<BTreeMap<Seq, usize>>,
    /// Serializes collection definitions (id choice and name check).
    defining: Mutex<()>,
    catalog: Catalog,
    _lock: DirLock,
}

impl Core {
    /// Take the directory `dir` (creating it), load the catalog, and open the
    /// log. Returns the core and whether the database is new (an empty log).
    /// Engines are opened by the caller after this and before
    /// [`recover`](Self::recover).
    pub(crate) fn open(dir: &Path) -> Result<(Core, bool)> {
        fs::create_dir(dir)?;
        let lock = DirLock::acquire(dir)?;
        let core_dir = dir.join("core");
        fs::create_dir(&core_dir)?;
        let catalog = Catalog::open(&core_dir)?;
        let log = CommitLog::open(&core_dir.join("log"))?;
        let new_database = log.is_empty();
        if new_database && !catalog.is_empty() {
            return Err(Error::corrupt("the commit log (records missing)", 0));
        }
        let core = Core {
            dir: dir.to_path_buf(),
            log,
            commit: Mutex::new(CommitState::default()),
            group: Mutex::new(Group::default()),
            written: Condvar::new(),
            applied: Mutex::new(0),
            turn: Condvar::new(),
            visible: AtomicU64::new(0),
            halted: AtomicBool::new(false),
            snapshots: Mutex::new(BTreeMap::new()),
            defining: Mutex::new(()),
            catalog,
            _lock: lock,
        };
        Ok((core, new_database))
    }

    /// Replay the log into the engines and publish the last sequence number.
    /// For a new database, define `defaults` in its first record.
    pub(crate) fn recover(
        &self,
        engines: &dyn Registry,
        new_database: bool,
        defaults: &[Collection],
    ) -> Result<()> {
        let last = self.replay(engines)?;
        self.commit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last = last;
        *self.applied.lock().unwrap_or_else(PoisonError::into_inner) = last;
        self.group
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .durable = last;
        self.visible.store(last, Ordering::Release);
        if new_database && !defaults.is_empty() {
            let staged = CatalogStaged::define(defaults.to_vec());
            self.write_or_fail(engines, Kind::Catalog, 0, &[&staged])?;
        }
        Ok(())
    }

    /// The database directory.
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    /// The catalog.
    pub(crate) fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// The highest sequence number visible to readers.
    pub(crate) fn visible(&self) -> Seq {
        self.visible.load(Ordering::Acquire)
    }

    /// True after a failed write: every later commit is refused.
    pub(crate) fn halted(&self) -> bool {
        self.halted.load(Ordering::Acquire)
    }

    /// Register a snapshot at the visible sequence number for a transaction.
    pub(crate) fn snapshot(&self) -> SnapshotGuard<'_> {
        let mut snapshots = self
            .snapshots
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let seq = self.visible.load(Ordering::Acquire);
        *snapshots.entry(seq).or_insert(0) += 1;
        SnapshotGuard { core: self, seq }
    }

    /// Commit the staged work of one transaction, taken at `snapshot`.
    /// Work with nothing staged is left out; with nothing at all, nothing is
    /// written.
    pub(crate) fn commit(
        &self,
        engines: &dyn Registry,
        snapshot: Seq,
        staged: &[&dyn Staged],
    ) -> std::result::Result<(), Attempt> {
        let parts: Vec<&dyn Staged> = staged.iter().copied().filter(|w| !w.is_empty()).collect();
        if parts.is_empty() {
            return Ok(());
        }
        self.write(engines, Kind::Commit, snapshot, &parts)
    }

    /// Create a collection of `engine` named `name`, after the engine has
    /// checked `definition`. Returns the new collection's id.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] when a collection has that name.
    /// - [`Error::Invalid`] when the name or definition is refused, or the
    ///   engine is not hosted.
    /// - [`Error::Storage`] as for any commit.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn define_collection(
        &self,
        engines: &dyn Registry,
        engine: EngineId,
        name: &str,
        definition: &[u8],
    ) -> Result<u32> {
        if name.is_empty() || name.len() > MAX_NAME {
            return Err(Error::invalid("collection name", "must be 1 to 64 bytes"));
        }
        let hosted = engines
            .get(engine)
            .ok_or_else(|| Error::invalid("engine", "not hosted by this database"))?;
        hosted.define(definition)?;
        let _defining = self.defining.lock().unwrap_or_else(PoisonError::into_inner);
        if self.catalog.named(name).is_some() {
            return Err(Error::AlreadyExists { what: "collection" });
        }
        let id = self
            .catalog
            .next_id()
            .ok_or_else(|| Error::invalid("collection", "no id left"))?;
        let staged = CatalogStaged::define(vec![Collection {
            id,
            engine,
            name: name.to_owned().into(),
            definition: definition.to_vec().into(),
        }]);
        self.write_or_fail(engines, Kind::Catalog, self.visible(), &[&staged])?;
        Ok(id)
    }

    /// Write every engine's applied changes to its own files. Best effort:
    /// the log holds every commit, so a failure only lengthens the next
    /// replay.
    pub(crate) fn checkpoint(&self, engines: &dyn Registry) {
        let _ = self.catalog.checkpoint();
        engines.each(&mut |engine| {
            let _ = engine.checkpoint();
        });
    }

    fn write_or_fail(
        &self,
        engines: &dyn Registry,
        kind: Kind,
        snapshot: Seq,
        staged: &[&dyn Staged],
    ) -> Result<()> {
        match self.write(engines, kind, snapshot, staged) {
            Ok(()) => Ok(()),
            Err(Attempt::Failed(err)) => Err(err),
            Err(Attempt::Conflict) => Err(Error::Conflict),
        }
    }

    /// The commit pipeline (see the module documentation): sequence and
    /// append under the lock, sync outside it, apply and publish in turn.
    fn write(
        &self,
        engines: &dyn Registry,
        kind: Kind,
        snapshot: Seq,
        staged: &[&dyn Staged],
    ) -> std::result::Result<(), Attempt> {
        let (seq, bytes) = self.sequence(engines, kind, snapshot, staged)?;
        let result = self.complete(engines, seq, &bytes);
        let mut state = self.commit.lock().unwrap_or_else(PoisonError::into_inner);
        state.in_flight -= 1;
        drop(state);
        if result.is_ok() {
            self.reclaim(engines);
        }
        result.map_err(Attempt::Failed)
    }

    /// Part 1, under the sequencer lock: validate, number, encode, reserve,
    /// queue. Returns the sequence number and the record bytes.
    fn sequence(
        &self,
        engines: &dyn Registry,
        kind: Kind,
        snapshot: Seq,
        staged: &[&dyn Staged],
    ) -> std::result::Result<(Seq, Arc<[u8]>), Attempt> {
        let mut state = self.commit.lock().unwrap_or_else(PoisonError::into_inner);
        if self.halted.load(Ordering::Acquire) {
            return Err(Attempt::Failed(halted_error()));
        }
        if state.in_flight >= MAX_IN_FLIGHT {
            return Err(Attempt::Failed(Error::Busy {
                what: "commit queue",
            }));
        }
        for work in staged {
            if work.validate(snapshot).is_err() {
                return Err(Attempt::Conflict);
            }
        }

        let seq = state.last + 1;
        let class = if staged.iter().any(|w| w.priority()) {
            Class::Priority
        } else {
            Class::Durable
        };
        let ids: Vec<EngineId> = staged.iter().map(|w| w.engine()).collect();
        // One buffer per commit: it must outlive the lock until its apply.
        let mut record = RecordWriter::new(seq, kind, class, &ids, Vec::new())?;
        for work in staged {
            let format = self.engine(engines, work.engine())?.format();
            let body = record.begin_section(work.engine(), format, work.collection())?;
            work.encode(seq, body)?;
            record.end_section()?;
        }
        let bytes = record.finish()?;
        if bytes.len() > MAX_RECORD {
            return Err(Attempt::Failed(Error::invalid(
                "commit",
                "larger than 16 MiB",
            )));
        }

        let bytes: Arc<[u8]> = bytes.into();
        for work in staged {
            work.reserve(seq);
        }
        state.last = seq;
        state.in_flight += 1;
        // Queued while the sequencer lock is held, so the queue stays in
        // sequence order.
        self.group
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pending
            .push((seq, Arc::clone(&bytes)));
        Ok((seq, bytes))
    }

    /// Part 2: return once the record at `seq` is on stable storage, writing
    /// the queued batch when no other commit is.
    fn make_durable(&self, seq: Seq) -> Result<()> {
        let mut group = self.group.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if group.durable >= seq {
                return Ok(());
            }
            if self.halted() {
                return Err(halted_error());
            }
            if group.writing {
                group = self
                    .written
                    .wait(group)
                    .unwrap_or_else(PoisonError::into_inner);
                continue;
            }
            let batch = std::mem::take(&mut group.pending);
            let Some(&(last, _)) = batch.last() else {
                // Not durable, not queued, no writer: only a halt does this.
                return Err(halted_error());
            };
            group.writing = true;
            drop(group);

            let written = batch
                .iter()
                .try_for_each(|(_, bytes)| self.log.append(bytes))
                .and_then(|()| self.log.sync());

            group = self.group.lock().unwrap_or_else(PoisonError::into_inner);
            group.writing = false;
            if let Err(err) = written {
                // Never retried: the bytes may already be gone from the
                // cache. Recovery after a restart decides what is durable.
                drop(group);
                self.halt();
                return Err(err);
            }
            group.durable = last;
            self.written.notify_all();
        }
    }

    /// Parts 2 and 3: sync, then wait for the commit before this one, apply
    /// from the encoded bytes (the path recovery takes), and publish.
    fn complete(&self, engines: &dyn Registry, seq: Seq, bytes: &[u8]) -> Result<()> {
        self.make_durable(seq)?;
        let mut applied = self.applied.lock().unwrap_or_else(PoisonError::into_inner);
        while *applied + 1 != seq {
            if self.halted() {
                return Err(halted_error());
            }
            applied = self
                .turn
                .wait(applied)
                .unwrap_or_else(PoisonError::into_inner);
        }
        if self.halted() {
            return Err(halted_error());
        }
        let done = record::decode(bytes, 0).and_then(|view| self.apply_record(engines, &view));
        if let Err(err) = done {
            drop(applied);
            self.halt();
            return Err(err);
        }
        *applied = seq;
        self.visible.store(seq, Ordering::Release);
        drop(applied);
        self.turn.notify_all();
        Ok(())
    }

    /// Stop every later commit and wake every waiting commit, so it fails
    /// instead of waiting for a record that will not be written or applied.
    /// Called with neither the writer's queue nor the turn lock held.
    fn halt(&self) {
        self.halted.store(true, Ordering::Release);
        {
            let _group = self.group.lock().unwrap_or_else(PoisonError::into_inner);
            self.written.notify_all();
        }
        let _applied = self.applied.lock().unwrap_or_else(PoisonError::into_inner);
        self.turn.notify_all();
    }

    /// Replay the log into the engines. Returns the last sequence number.
    fn replay(&self, engines: &dyn Registry) -> Result<Seq> {
        let mut floor = self.catalog.durable_through();
        let mut top = floor;
        engines.each(&mut |engine| {
            floor = floor.min(engine.durable_through());
            top = top.max(engine.durable_through());
        });
        let mut last: Seq = 0;
        self.log.replay(|lsn, bytes| {
            let view = record::decode(bytes, lsn)?;
            if view.seq != last + 1 {
                return Err(Error::corrupt("the commit log sequence", view.seq));
            }
            last = view.seq;
            if view.seq <= floor {
                return Ok(());
            }
            self.apply_record(engines, &view)
        })?;
        // An engine holding a commit the log does not have means the log
        // lost records: refuse to open rather than serve a mix.
        if top > last {
            return Err(Error::corrupt("the commit log (ends early)", last));
        }
        Ok(last)
    }

    /// Hand each section of a decoded record to its engine.
    fn apply_record(&self, engines: &dyn Registry, view: &RecordView<'_>) -> Result<()> {
        for section in &view.sections {
            let catalog_section = section.engine == EngineId::CATALOG;
            if catalog_section != (view.kind == Kind::Catalog) {
                return Err(Error::corrupt("a log record (kind)", view.seq));
            }
            if section.flags != 0 {
                return Err(Error::corrupt("a log section (flags)", view.seq));
            }
            if !catalog_section && !self.catalog.binds(section.collection, section.engine) {
                return Err(Error::corrupt("a log section (collection)", view.seq));
            }
            let engine = self.engine(engines, section.engine)?;
            debug_assert_eq!(engine.id(), section.engine);
            engine.apply(view.seq, section.collection, section.format, section.body)?;
        }
        Ok(())
    }

    fn engine<'a>(&'a self, engines: &'a dyn Registry, id: EngineId) -> Result<&'a dyn Engine> {
        if id == EngineId::CATALOG {
            return Ok(&self.catalog);
        }
        engines.get(id).ok_or_else(|| id.missing())
    }

    /// Let engines drop state kept for snapshots older than the oldest
    /// running one.
    fn reclaim(&self, engines: &dyn Registry) {
        let watermark = {
            let snapshots = self
                .snapshots
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            snapshots
                .keys()
                .next()
                .copied()
                .unwrap_or_else(|| self.visible.load(Ordering::Acquire))
        };
        engines.each(&mut |engine| engine.reclaim(watermark));
    }
}

fn halted_error() -> Error {
    Error::storage("committing", "writes stopped after an earlier failed write")
}

/// A running transaction's snapshot, registered so conflict tables keep the
/// entries it may conflict with.
#[derive(Debug)]
pub(crate) struct SnapshotGuard<'c> {
    core: &'c Core,
    seq: Seq,
}

impl SnapshotGuard<'_> {
    /// The snapshot's sequence number.
    pub(crate) fn seq(&self) -> Seq {
        self.seq
    }
}

impl Drop for SnapshotGuard<'_> {
    fn drop(&mut self) {
        let mut snapshots = self
            .core
            .snapshots
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = snapshots.get_mut(&self.seq) {
            *count -= 1;
            if *count == 0 {
                let _ = snapshots.remove(&self.seq);
            }
        }
    }
}
