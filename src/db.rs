//! The database: open and recovery, the commit pipeline, transactions.

use std::{
    collections::BTreeMap,
    fmt,
    path::{Path, PathBuf},
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

#[cfg(feature = "auth")]
use crate::auth::{Auth, AuthEngine, AuthStaged, AuthTx};
#[cfg(feature = "content")]
use crate::content::{Content, ContentEngine, ContentStaged, ContentTx};
use crate::{
    core::{
        catalog::{Catalog, DEFAULT_REALM, DEFAULT_SPACE},
        fs::{self, DirLock},
        keys,
        log::{CommitLog, MAX_RECORD},
        record::{self, Class, Kind, RecordView, RecordWriter, Seq},
    },
    engine::{Engine, EngineId, Staged},
    error::{Error, Result},
};

/// Times a commit closure runs before [`Error::Conflict`].
const ATTEMPTS: usize = 4;

/// Open (or create) the database in the directory `path`.
///
/// A new directory gets a new database. An existing one is recovered: the
/// commit log is replayed into every engine, so every commit that returned
/// `Ok` before a crash is back, and none that did not return appears in part.
/// Nothing is served until recovery has finished.
///
/// One process owns a directory at a time.
///
/// ```no_run
/// # fn main() -> nex_db::Result<()> {
/// let db = nex_db::open("data/site")?;
/// # let _ = db;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// - [`Error::Locked`] when another process (or another `Database` in this
///   process) owns the directory.
/// - [`Error::KeyUnavailable`] when the key file of an existing database is
///   missing or damaged. The database stays closed.
/// - [`Error::Corrupt`] when the log, the catalog, or a store fails a check
///   before the log's tail. The database stays closed.
/// - [`Error::Storage`] when the operating system refuses an operation.
pub fn open(path: impl AsRef<Path>) -> Result<Database> {
    Database::open(path)
}

/// The commit pipeline's state, behind the commit lock.
#[derive(Debug, Default)]
struct CommitState {
    /// The last committed sequence number.
    last: Seq,
    /// Reused record buffer.
    buf: Vec<u8>,
}

/// Why one commit attempt did not land.
enum Attempt {
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

/// An open database.
///
/// `Database` is `Send` and `Sync`: share it between threads by reference or
/// behind an `Arc`. Dropping it writes the engines' buffered changes to their
/// own files (best effort; the commit log already holds them) and releases
/// the directory.
pub struct Database {
    dir: PathBuf,
    log: CommitLog,
    commit: Mutex<CommitState>,
    /// The highest sequence number applied in every engine it touched.
    visible: AtomicU64,
    /// Set after a failed log write or apply: no further commits.
    halted: AtomicBool,
    /// Snapshots of running transactions, with their counts.
    snapshots: Mutex<BTreeMap<Seq, usize>>,
    catalog: Catalog,
    #[cfg(feature = "auth")]
    pub(crate) auth: AuthEngine,
    #[cfg(feature = "content")]
    pub(crate) content: ContentEngine,
    _lock: DirLock,
}

impl fmt::Debug for Database {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Database")
            .field("dir", &self.dir)
            .field("visible", &self.visible.load(Ordering::Acquire))
            .field("halted", &self.halted.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl Database {
    /// Open (or create) the database in `path`. Same as [`open`](crate::open).
    ///
    /// # Errors
    ///
    /// See [`open`](crate::open).
    pub fn open(path: impl AsRef<Path>) -> Result<Database> {
        let dir = path.as_ref().to_path_buf();
        fs::create_dir(&dir)?;
        let lock = DirLock::acquire(&dir)?;
        let core_dir = dir.join("core");
        let auth_dir = dir.join("auth");
        fs::create_dir(&core_dir)?;
        fs::create_dir(&auth_dir)?;

        let catalog = Catalog::open(&core_dir)?;
        let log = CommitLog::open(&core_dir.join("log"))?;
        let new_database = log.is_empty();
        if new_database {
            if !catalog.is_empty() {
                return Err(Error::corrupt("the commit log (records missing)", 0));
            }
            keys::create_if_missing(&auth_dir)?;
        }

        #[cfg(feature = "auth")]
        let auth = {
            let root = keys::load(&auth_dir)?;
            AuthEngine::open(&auth_dir.join("accounts"), &root, DEFAULT_REALM.id)?
        };
        #[cfg(feature = "content")]
        let content = ContentEngine::open(&dir.join("content").join("store"), DEFAULT_SPACE.id)?;

        let db = Database {
            dir,
            log,
            commit: Mutex::new(CommitState::default()),
            visible: AtomicU64::new(0),
            halted: AtomicBool::new(false),
            snapshots: Mutex::new(BTreeMap::new()),
            catalog,
            #[cfg(feature = "auth")]
            auth,
            #[cfg(feature = "content")]
            content,
            _lock: lock,
        };

        let last = db.replay()?;
        db.commit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last = last;
        db.visible.store(last, Ordering::Release);

        if new_database {
            let staged = Catalog::bootstrap();
            match db.write(Kind::Catalog, Class::Durable, 0, &[&staged]) {
                Ok(()) => {}
                Err(Attempt::Failed(err)) => return Err(err),
                Err(Attempt::Conflict) => return Err(Error::Conflict),
            }
        }
        db.check_collections()?;
        Ok(db)
    }

    /// The directory the database lives in.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// The auth engine: sessions, accounts, passwords.
    #[cfg(feature = "auth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "auth")))]
    #[must_use]
    pub fn auth(&self) -> Auth<'_> {
        Auth { db: self }
    }

    /// The content engine: entities and routes.
    #[cfg(feature = "content")]
    #[cfg_attr(docsrs, doc(cfg(feature = "content")))]
    #[must_use]
    pub fn content(&self) -> Content<'_> {
        Content { db: self }
    }

    /// Run `f` as one atomic commit across every engine it touches.
    ///
    /// `f` stages typed operations on the [`Transaction`]; nothing is written
    /// until it returns `Ok`. Then the commit is checked against concurrent
    /// commits (snapshot isolation: it conflicts when a key it writes was
    /// committed after it started), written to the log as one record, synced,
    /// and applied to each engine. When `commit` returns `Ok`, the commit
    /// survives a crash. When `f` returns an error, nothing is written and the
    /// error is returned.
    ///
    /// On a conflict `f` runs again, up to four times in all, so `f` must not
    /// have side effects outside the transaction. Do slow work, such as
    /// hashing a password, before calling `commit`.
    ///
    /// ```no_run
    /// # #[cfg(all(feature = "auth", feature = "content"))]
    /// # fn main() -> nex_db::Result<()> {
    /// use nex_db::Entity;
    ///
    /// let db = nex_db::open("data/site")?;
    /// let password = db.auth().hash_password("correct horse battery staple")?;
    /// let account = db.commit(|tx| {
    ///     let account = tx.auth().create_account("ann@example.com", &password)?;
    ///     tx.content().create(Entity::new("profile").field("account", account).path("/u/ann"))?;
    ///     Ok(account)
    /// })?;
    /// # let _ = account;
    /// # Ok(())
    /// # }
    /// # #[cfg(not(all(feature = "auth", feature = "content")))]
    /// # fn main() {}
    /// ```
    ///
    /// # Errors
    ///
    /// - Any error `f` returns, unchanged.
    /// - [`Error::Conflict`] when every attempt conflicted.
    /// - [`Error::Invalid`] when the commit is larger than 16 MiB.
    /// - [`Error::Storage`] when the log write or sync failed. The database
    ///   then refuses every later commit (reads continue); restart the
    ///   process so recovery can decide what is durable.
    pub fn commit<T, F>(&self, mut f: F) -> Result<T>
    where
        F: FnMut(&mut Transaction<'_>) -> Result<T>,
    {
        for _ in 0..ATTEMPTS {
            let snapshot = SnapshotGuard::begin(self);
            let mut tx = Transaction::new(self, snapshot.seq);
            let value = f(&mut tx)?;
            let staged = tx.staged();
            if staged.is_empty() {
                return Ok(value);
            }
            let class = if tx.is_priority() {
                Class::Priority
            } else {
                Class::Durable
            };
            match self.write(Kind::Commit, class, snapshot.seq, &staged) {
                Ok(()) => return Ok(value),
                Err(Attempt::Conflict) => {}
                Err(Attempt::Failed(err)) => return Err(err),
            }
        }
        Err(Error::Conflict)
    }

    /// The commit pipeline: validate, sequence, encode, log and sync, apply
    /// from the encoded bytes, publish.
    fn write(
        &self,
        kind: Kind,
        class: Class,
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
        let engines: Vec<EngineId> = staged.iter().map(|w| w.engine()).collect();
        let buf = std::mem::take(&mut state.buf);
        let mut record = RecordWriter::new(seq, kind, class, &engines, buf)?;
        for work in staged {
            let format = self.engine(work.engine())?.format();
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
        let applied = record::decode(&bytes, 0).and_then(|view| self.apply_record(&view));
        if let Err(err) = applied {
            self.halted.store(true, Ordering::Release);
            return Err(Attempt::Failed(err));
        }
        state.last = seq;
        state.buf = bytes;
        self.visible.store(seq, Ordering::Release);
        drop(state);
        self.reclaim();
        Ok(())
    }

    /// Replay the log into the engines. Returns the last sequence number.
    fn replay(&self) -> Result<Seq> {
        let engines = self.engines();
        let floor = engines
            .iter()
            .map(|e| e.durable_through())
            .min()
            .unwrap_or(0);
        let top = engines
            .iter()
            .map(|e| e.durable_through())
            .max()
            .unwrap_or(0);
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
            self.apply_record(&view)
        })?;
        // An engine holding a commit the log does not have means the log
        // lost records: refuse to open rather than serve a mix.
        if top > last {
            return Err(Error::corrupt("the commit log (ends early)", last));
        }
        Ok(last)
    }

    /// Hand each section of a decoded record to its engine.
    fn apply_record(&self, view: &RecordView<'_>) -> Result<()> {
        for section in &view.sections {
            let catalog_section = section.engine == EngineId::CATALOG;
            if catalog_section != (view.kind == Kind::Catalog) {
                return Err(Error::corrupt("a log record (kind)", view.seq));
            }
            if section.flags != 0 {
                return Err(Error::corrupt("a log section (flags)", view.seq));
            }
            if !catalog_section {
                let bound = self
                    .catalog
                    .collection(section.collection)
                    .is_some_and(|c| c.engine == section.engine);
                if !bound {
                    return Err(Error::corrupt("a log section (collection)", view.seq));
                }
            }
            let engine = self.engine(section.engine)?;
            debug_assert_eq!(engine.id(), section.engine);
            engine.apply(view.seq, section.collection, section.format, section.body)?;
        }
        Ok(())
    }

    /// The default collections must be bound to their engines.
    fn check_collections(&self) -> Result<()> {
        for expected in [DEFAULT_REALM, DEFAULT_SPACE] {
            if self.catalog.collection(expected.id) != Some(expected) {
                return Err(Error::corrupt("the catalog (default collections)", 0));
            }
        }
        Ok(())
    }

    fn engine(&self, id: EngineId) -> Result<&dyn Engine> {
        match id {
            EngineId::CATALOG => Ok(&self.catalog),
            #[cfg(feature = "auth")]
            EngineId::AUTH => Ok(&self.auth),
            #[cfg(not(feature = "auth"))]
            EngineId::AUTH => Err(Error::invalid(
                "database",
                "uses the auth engine, which this build does not include",
            )),
            #[cfg(feature = "content")]
            EngineId::CONTENT => Ok(&self.content),
            #[cfg(not(feature = "content"))]
            EngineId::CONTENT => Err(Error::invalid(
                "database",
                "uses the content engine, which this build does not include",
            )),
            _ => Err(Error::corrupt("a log section (engine)", u64::from(id.0))),
        }
    }

    fn engines(&self) -> Vec<&dyn Engine> {
        #[allow(unused_mut)]
        let mut engines: Vec<&dyn Engine> = vec![&self.catalog];
        #[cfg(feature = "auth")]
        engines.push(&self.auth);
        #[cfg(feature = "content")]
        engines.push(&self.content);
        engines
    }

    /// Prune conflict tables below the oldest running snapshot.
    fn reclaim(&self) {
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
        #[cfg(feature = "auth")]
        self.auth.reclaim(watermark);
        #[cfg(feature = "content")]
        self.content.reclaim(watermark);
        let _ = watermark;
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        // Best effort: the log holds every commit, so a failure here only
        // means a longer replay at the next open.
        for engine in self.engines() {
            let _ = engine.checkpoint();
        }
    }
}

/// A running transaction's snapshot, registered so conflict tables keep the
/// entries it may conflict with.
struct SnapshotGuard<'db> {
    db: &'db Database,
    seq: Seq,
}

impl<'db> SnapshotGuard<'db> {
    fn begin(db: &'db Database) -> Self {
        let mut snapshots = db.snapshots.lock().unwrap_or_else(PoisonError::into_inner);
        let seq = db.visible.load(Ordering::Acquire);
        *snapshots.entry(seq).or_insert(0) += 1;
        SnapshotGuard { db, seq }
    }
}

impl Drop for SnapshotGuard<'_> {
    fn drop(&mut self) {
        let mut snapshots = self
            .db
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

/// One commit in progress, handed to the closure of [`Database::commit`].
///
/// Each engine's operations are reached through its method
/// ([`auth`](Transaction::auth), [`content`](Transaction::content)). An
/// engine the transaction does not touch gets no part in the commit.
pub struct Transaction<'db> {
    #[cfg_attr(not(any(feature = "auth", feature = "content")), allow(dead_code))]
    db: &'db Database,
    snapshot: Seq,
    #[cfg(feature = "auth")]
    auth: Option<AuthStaged<'db>>,
    #[cfg(feature = "content")]
    content: Option<ContentStaged<'db>>,
}

impl fmt::Debug for Transaction<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transaction")
            .field("snapshot", &self.snapshot)
            .finish_non_exhaustive()
    }
}

impl<'db> Transaction<'db> {
    fn new(db: &'db Database, snapshot: Seq) -> Self {
        Transaction {
            db,
            snapshot,
            #[cfg(feature = "auth")]
            auth: None,
            #[cfg(feature = "content")]
            content: None,
        }
    }

    /// Auth operations in this transaction.
    #[cfg(feature = "auth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "auth")))]
    pub fn auth(&mut self) -> AuthTx<'_, 'db> {
        let db = self.db;
        AuthTx {
            staged: self.auth.get_or_insert_with(|| AuthStaged::new(&db.auth)),
        }
    }

    /// Content operations in this transaction.
    #[cfg(feature = "content")]
    #[cfg_attr(docsrs, doc(cfg(feature = "content")))]
    pub fn content(&mut self) -> ContentTx<'_, 'db> {
        let db = self.db;
        ContentTx {
            staged: self
                .content
                .get_or_insert_with(|| ContentStaged::new(&db.content)),
        }
    }

    /// The engines' staged work that has something in it.
    fn staged(&self) -> Vec<&dyn Staged> {
        #[allow(unused_mut)]
        let mut staged: Vec<&dyn Staged> = Vec::new();
        #[cfg(feature = "auth")]
        if let Some(work) = &self.auth {
            staged.push(work);
        }
        #[cfg(feature = "content")]
        if let Some(work) = &self.content {
            staged.push(work);
        }
        staged.retain(|work| !work.is_empty());
        staged
    }

    fn is_priority(&self) -> bool {
        #[cfg(feature = "auth")]
        if let Some(work) = &self.auth {
            return work.has_revocation();
        }
        false
    }
}
