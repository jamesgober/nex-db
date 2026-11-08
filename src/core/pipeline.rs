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
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use super::{
    catalog::{Catalog, CatalogStaged, Collection, MAX_NAME},
    fs::{self, DirLock},
    log::{CommitLog, MAX_RECORD},
    record::{self, Class, Kind, RecordView, RecordWriter, Seq},
    turn::{Stop, Turnstile},
};
use crate::{
    engine::{Engine, EngineId, Registry, Staged},
    error::{Error, Result},
    feed::{Change, FeedLog},
};

/// Times a commit closure runs before [`Error::Conflict`].
pub(crate) const ATTEMPTS: usize = 4;

/// How long a snapshot may run: a read past it fails with
/// `Error::SnapshotTooOld`, and a commit whose closure ran longer runs again
/// on a new snapshot. Older snapshots are left out of the watermark, so they
/// hold no memory.
pub(crate) const MAX_SNAPSHOT_AGE: Duration = Duration::from_secs(60);

/// During recovery, engines drop their snapshot versions every this many
/// records (no snapshot runs before recovery ends).
const REPLAY_RECLAIM_EVERY: u64 = 1024;

/// Log bytes written between checkpoints, by default: 64 MiB.
pub(crate) const CHECKPOINT_EVERY: u64 = 64 * 1024 * 1024;

/// Commits between taking a sequence number and becoming visible, before a
/// new commit is refused with `Error::Busy`. Bounds the memory held by
/// encoded records waiting for their turn.
const MAX_IN_FLIGHT: usize = 4096;

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
    /// The writer's queue, the apply turn, and the visible mark. Its queue
    /// is taken after `commit` when both are held.
    order: Turnstile<Arc<[u8]>>,
    /// Running snapshots: how many at each sequence number, and when the
    /// oldest of them started.
    snapshots: Mutex<BTreeMap<Seq, (usize, Instant)>>,
    /// Serializes collection definitions (id choice and name check).
    defining: Mutex<()>,
    /// One checkpoint at a time.
    checkpointing: Mutex<()>,
    /// Log bytes written since the last checkpoint.
    since_checkpoint: AtomicU64,
    /// Log bytes that start a checkpoint.
    checkpoint_every: AtomicU64,
    catalog: Catalog,
    /// Recent changes for the change feed.
    feed: FeedLog,
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
            order: Turnstile::new(),
            snapshots: Mutex::new(BTreeMap::new()),
            defining: Mutex::new(()),
            checkpointing: Mutex::new(()),
            since_checkpoint: AtomicU64::new(0),
            checkpoint_every: AtomicU64::new(CHECKPOINT_EVERY),
            catalog,
            feed: FeedLog::default(),
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
        // The engines hold everything replay read: drop what the last
        // checkpoint covers.
        let mut floor = Seq::MAX;
        engines.each(&mut |engine| floor = floor.min(engine.durable_through()));
        self.truncate_held(floor)?;
        self.commit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last = last;
        self.order.start_at(last);
        self.feed.reset(last);
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

    /// The change feed's window.
    pub(crate) fn feed(&self) -> &FeedLog {
        &self.feed
    }

    /// The highest sequence number visible to readers.
    pub(crate) fn visible(&self) -> Seq {
        self.order.visible()
    }

    /// After a conflict: return once every commit sequenced so far is
    /// visible, so a retry's snapshot holds the commit it lost to. Without
    /// this wait a retry can start before the winner is visible and lose
    /// again on every attempt.
    pub(crate) fn wait_for_sequenced(&self) {
        let last = self
            .commit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last;
        self.order.wait_visible(last);
    }

    /// True after a failed write: every later commit is refused.
    pub(crate) fn halted(&self) -> bool {
        self.order.halted()
    }

    /// Register a snapshot at the visible sequence number for a transaction.
    pub(crate) fn snapshot(&self) -> SnapshotGuard<'_> {
        let mut snapshots = self
            .snapshots
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let seq = self.order.visible();
        let started = Instant::now();
        snapshots.entry(seq).or_insert((0, started)).0 += 1;
        SnapshotGuard {
            core: self,
            seq,
            started,
        }
    }

    /// Commit the staged work of one transaction, taken at `snapshot`.
    /// Work with nothing staged is left out; with nothing at all, nothing is
    /// written.
    pub(crate) fn commit(
        &self,
        engines: &dyn Registry,
        snapshot: &SnapshotGuard<'_>,
        staged: &[&dyn Staged],
    ) -> std::result::Result<Option<Seq>, Attempt> {
        let parts: Vec<&dyn Staged> = staged.iter().copied().filter(|w| !w.is_empty()).collect();
        if parts.is_empty() {
            return Ok(None);
        }
        // Conflict entries older than the watermark are gone, and an expired
        // snapshot is not in the watermark: run the closure again.
        if snapshot.expired() {
            return Err(Attempt::Conflict);
        }
        self.write(engines, Kind::Commit, snapshot.seq(), &parts)
            .map(Some)
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

    /// Start a checkpoint after `bytes` more log bytes (at least 1).
    pub(crate) fn set_checkpoint_every(&self, bytes: u64) {
        self.checkpoint_every.store(bytes.max(1), Ordering::Release);
    }

    /// Make every engine's files hold everything visible now. With
    /// `truncate`, then drop the log records every engine holds; the record
    /// at the lowest mark stays, so the log is never empty and replay can
    /// check where it starts. Closing the database checkpoints without
    /// truncating, so a clean close leaves the whole log; the next open
    /// truncates once recovery is done.
    ///
    /// # Errors
    ///
    /// The first engine's error; the log is then not truncated.
    pub(crate) fn checkpoint(&self, engines: &dyn Registry, truncate: bool) -> Result<()> {
        let one = self
            .checkpointing
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.checkpoint_locked(engines, truncate, &one)
    }

    /// The checkpoint itself, with the checkpoint lock held.
    fn checkpoint_locked(
        &self,
        engines: &dyn Registry,
        truncate: bool,
        _one: &MutexGuard<'_, ()>,
    ) -> Result<()> {
        if self.halted() {
            return Err(halted_error());
        }
        let upto = self.visible();
        let mut floor = Seq::MAX;
        let mut failed = None;
        engines.each(&mut |engine| match engine.checkpoint(upto) {
            Ok(mark) => floor = floor.min(mark),
            Err(err) => failed = failed.take().or(Some(err)),
        });
        if let Some(err) = failed {
            return Err(err);
        }
        self.since_checkpoint.store(0, Ordering::Release);
        if truncate {
            self.truncate_held(floor)?;
        }
        Ok(())
    }

    /// Drop the log records below `floor`, the lowest mark of all engines.
    fn truncate_held(&self, floor: Seq) -> Result<()> {
        if floor != Seq::MAX && floor > 1 {
            self.log.truncate_below(floor)?;
        }
        Ok(())
    }

    /// Run a checkpoint when enough log was written since the last one and
    /// no other is running. Best effort: a failed checkpoint leaves the log
    /// as it is.
    fn maybe_checkpoint(&self, engines: &dyn Registry) {
        let due = self.since_checkpoint.load(Ordering::Acquire)
            >= self.checkpoint_every.load(Ordering::Acquire);
        if !due {
            return;
        }
        // Another commit is already checkpointing: leave it to that one.
        if let Ok(one) = self.checkpointing.try_lock() {
            let _ = self.checkpoint_locked(engines, true, &one);
        }
    }

    fn write_or_fail(
        &self,
        engines: &dyn Registry,
        kind: Kind,
        snapshot: Seq,
        staged: &[&dyn Staged],
    ) -> Result<()> {
        match self.write(engines, kind, snapshot, staged) {
            Ok(_) => Ok(()),
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
    ) -> std::result::Result<Seq, Attempt> {
        let (seq, bytes) = self.sequence(engines, kind, snapshot, staged)?;
        let result = self.complete(engines, seq, &bytes);
        let mut state = self.commit.lock().unwrap_or_else(PoisonError::into_inner);
        state.in_flight -= 1;
        drop(state);
        if result.is_ok() {
            self.reclaim(engines);
            self.maybe_checkpoint(engines);
        }
        result.map(|()| seq).map_err(Attempt::Failed)
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
        if self.order.halted() {
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
            let flags = if work.sealed() { record::SEALED } else { 0 };
            let body = record.begin_section(work.engine(), flags, format, work.collection())?;
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

        let _ = self
            .since_checkpoint
            .fetch_add(bytes.len() as u64, Ordering::AcqRel);
        let bytes: Arc<[u8]> = bytes.into();
        for work in staged {
            work.reserve(seq);
        }
        state.last = seq;
        state.in_flight += 1;
        // Queued while the sequencer lock is held, so the queue stays in
        // sequence order.
        self.order.queue(seq, Arc::clone(&bytes));
        Ok((seq, bytes))
    }

    /// Parts 2 and 3: make the record durable (writing the queued batch
    /// when no other commit is), then wait for the commit before this one,
    /// apply from the encoded bytes (the path recovery takes), and publish.
    fn complete(&self, engines: &dyn Registry, seq: Seq, bytes: &[u8]) -> Result<()> {
        self.order
            .make_durable(seq, |batch| {
                batch
                    .iter()
                    .try_for_each(|(_, bytes)| self.log.append(bytes))
                    .and_then(|()| self.log.sync())
            })
            .map_err(stopped)?;
        self.order
            .complete(seq, || {
                let mut changes = Vec::new();
                record::decode(bytes, 0)
                    .and_then(|view| self.apply_record(engines, &view, &mut changes))?;
                // In commit order, before the commit is visible.
                self.feed.push(seq, changes);
                Ok(())
            })
            .map_err(stopped)
    }

    /// Replay the log into the engines. Returns the last sequence number.
    fn replay(&self, engines: &dyn Registry) -> Result<Seq> {
        // Engines skip what they hold; the catalog file holds every catalog
        // change it applied, so replay never skips past it.
        let mut engines_floor = Seq::MAX;
        let mut top = self.catalog.durable_through();
        engines.each(&mut |engine| {
            engines_floor = engines_floor.min(engine.durable_through());
            top = top.max(engine.durable_through());
        });
        let floor = engines_floor.min(self.catalog.durable_through());
        let mut last: Option<Seq> = None;
        self.log.replay(|lsn, bytes| {
            let view = record::decode(bytes, lsn)?;
            let expected = match last {
                Some(last) => last + 1,
                // A log truncated by a checkpoint starts later: every
                // engine must hold everything before its first record.
                None if view.seq == 1 || view.seq - 1 <= engines_floor => view.seq,
                None => return Err(Error::corrupt("the commit log (records missing)", view.seq)),
            };
            if view.seq != expected {
                return Err(Error::corrupt("the commit log sequence", view.seq));
            }
            last = Some(view.seq);
            if view.seq % REPLAY_RECLAIM_EVERY == 0 {
                engines.each(&mut |engine| engine.reclaim(view.seq - 1));
            }
            if view.seq <= floor {
                return Ok(());
            }
            // Changes replayed at open are not fed: a feed starts after
            // the last recovered commit.
            self.apply_record(engines, &view, &mut Vec::new())
        })?;
        let last = last.unwrap_or(0);
        // An engine holding a commit the log does not have means the log
        // lost records: refuse to open rather than serve a mix.
        if top > last {
            return Err(Error::corrupt("the commit log (ends early)", last));
        }
        Ok(last)
    }

    /// Hand each section of a decoded record to its engine.
    fn apply_record(
        &self,
        engines: &dyn Registry,
        view: &RecordView<'_>,
        changes: &mut Vec<Change>,
    ) -> Result<()> {
        for section in &view.sections {
            let catalog_section = section.engine == EngineId::CATALOG;
            if catalog_section != (view.kind == Kind::Catalog) {
                return Err(Error::corrupt("a log record (kind)", view.seq));
            }
            if section.flags & !record::SEALED != 0 {
                return Err(Error::corrupt("a log section (flags)", view.seq));
            }
            if !catalog_section && !self.catalog.binds(section.collection, section.engine) {
                return Err(Error::corrupt("a log section (collection)", view.seq));
            }
            let engine = self.engine(engines, section.engine)?;
            debug_assert_eq!(engine.id(), section.engine);
            engine.apply(view.seq, section, changes)?;
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
                .iter()
                .find(|(_, (_, started))| started.elapsed() < MAX_SNAPSHOT_AGE)
                .map(|(seq, _)| *seq)
                .unwrap_or_else(|| self.order.visible())
        };
        engines.each(&mut |engine| engine.reclaim(watermark));
    }
}

fn halted_error() -> Error {
    Error::storage("committing", "writes stopped after an earlier failed write")
}

fn stopped(stop: Stop<Error>) -> Error {
    match stop {
        Stop::Halted => halted_error(),
        Stop::Failed(err) => err,
    }
}

/// A running transaction's snapshot, registered so conflict tables keep the
/// entries it may conflict with.
#[derive(Debug)]
pub(crate) struct SnapshotGuard<'c> {
    core: &'c Core,
    seq: Seq,
    started: Instant,
}

impl SnapshotGuard<'_> {
    /// The snapshot's sequence number.
    pub(crate) fn seq(&self) -> Seq {
        self.seq
    }

    /// True once the snapshot has run past [`MAX_SNAPSHOT_AGE`]: its
    /// versions may be gone.
    pub(crate) fn expired(&self) -> bool {
        self.started.elapsed() >= MAX_SNAPSHOT_AGE
    }
}

impl Drop for SnapshotGuard<'_> {
    fn drop(&mut self) {
        let mut snapshots = self
            .core
            .snapshots
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some((count, _)) = snapshots.get_mut(&self.seq) {
            *count -= 1;
            if *count == 0 {
                let _ = snapshots.remove(&self.seq);
            }
        }
    }
}
