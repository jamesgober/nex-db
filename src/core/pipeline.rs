//! The core: directory ownership, the commit pipeline, recovery, the catalog.
//!
//! [`Core`] knows engines only through the contract in [`crate::engine`]:
//! the database facade hands it a [`Registry`] of the engines it hosts, and
//! a commit's staged work as `&dyn Staged`. Nothing here names an engine, so
//! a new engine needs no change in this file.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Mutex, PoisonError,
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

/// The commit pipeline's state, behind the commit lock.
#[derive(Debug, Default)]
struct CommitState {
    /// The last committed sequence number.
    last: Seq,
    /// Reused record buffer.
    buf: Vec<u8>,
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

    /// The commit pipeline: validate, sequence, encode, log and sync, apply
    /// from the encoded bytes, publish.
    fn write(
        &self,
        engines: &dyn Registry,
        kind: Kind,
        snapshot: Seq,
        staged: &[&dyn Staged],
    ) -> std::result::Result<(), Attempt> {
        let mut state = self.commit.lock().unwrap_or_else(PoisonError::into_inner);
        if self.halted.load(Ordering::Acquire) {
            return Err(Attempt::Failed(Error::storage(
                "committing",
                "writes stopped after an earlier failed write",
            )));
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
        let buf = std::mem::take(&mut state.buf);
        let mut record = RecordWriter::new(seq, kind, class, &ids, buf)?;
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

        // A failed write or sync is never retried: the bytes may already be
        // gone from the page cache. Recovery after a restart decides.
        if let Err(err) = self.log.append_durable(&bytes) {
            self.halted.store(true, Ordering::Release);
            return Err(Attempt::Failed(err));
        }
        for work in staged {
            work.reserve(seq);
        }
        // Apply from the encoded bytes: the same path recovery takes.
        let applied = record::decode(&bytes, 0).and_then(|view| self.apply_record(engines, &view));
        if let Err(err) = applied {
            self.halted.store(true, Ordering::Release);
            return Err(Attempt::Failed(err));
        }
        state.last = seq;
        state.buf = bytes;
        self.visible.store(seq, Ordering::Release);
        drop(state);
        self.reclaim(engines);
        Ok(())
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
