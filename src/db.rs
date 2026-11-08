//! The database facade: open, the engines it hosts, transactions.
//!
//! The commit pipeline, recovery, and the catalog live in
//! [`Core`](crate::core::pipeline::Core); this module holds the typed engines
//! and hands them to the core through the [`Registry`] contract.

use std::{fmt, path::Path, sync::Arc};

#[cfg(feature = "auth")]
use crate::auth::{Auth, AuthEngine, AuthRead, AuthStaged, AuthTx};
#[cfg(feature = "content")]
use crate::content::{Content, ContentEngine, ContentRead, ContentStaged, ContentTx};
use crate::{
    core::{
        catalog::{DEFAULT_REALM, DEFAULT_SPACE},
        fs,
        keys::{self, Keys},
        pipeline::{ATTEMPTS, Attempt, CHECKPOINT_EVERY, Core, SnapshotGuard},
        record::Seq,
    },
    engine::{Engine, EngineId, Registry, Staged},
    error::{Error, Result},
    feed::{Feed, FeedLog, Position},
    observe::{CommitInfo, Health, Observer, Observers},
};

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

/// The engines this build hosts, apart from the catalog.
struct Engines {
    #[cfg(feature = "auth")]
    auth: AuthEngine,
    #[cfg(feature = "content")]
    content: ContentEngine,
}

impl Registry for Engines {
    fn get(&self, id: EngineId) -> Option<&dyn Engine> {
        match id {
            #[cfg(feature = "auth")]
            EngineId::AUTH => Some(&self.auth),
            #[cfg(feature = "content")]
            EngineId::CONTENT => Some(&self.content),
            _ => None,
        }
    }

    fn each(&self, f: &mut dyn FnMut(&dyn Engine)) {
        #[cfg(feature = "auth")]
        f(&self.auth);
        #[cfg(feature = "content")]
        f(&self.content);
        let _ = f;
    }
}

/// Opens a database with settings other than the defaults. Made by
/// [`Database::builder`].
///
/// ```no_run
/// # fn main() -> nex_db::Result<()> {
/// let db = nex_db::Database::builder("data/site")
///     .keys(nex_db::Keys::env("SITE_DB_KEY"))
///     .open()?;
/// # let _ = db;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[must_use]
pub struct Builder {
    dir: std::path::PathBuf,
    keys: Keys,
    checkpoint_every: u64,
    #[cfg_attr(not(feature = "auth"), allow(dead_code))]
    max_sessions: usize,
    observers: Observers,
}

impl Builder {
    /// Where the root key comes from. The default is a key file inside the
    /// database directory; see [`Keys`].
    pub fn keys(mut self, keys: Keys) -> Self {
        self.keys = keys;
        self
    }

    /// How much log to write between checkpoints, in bytes (default 64
    /// MiB). A checkpoint writes every engine's own files and drops the log
    /// records they hold, so the log, and the time an open takes, stay
    /// bounded. It runs on the thread of the commit that crosses the mark,
    /// after that commit is visible, and at close.
    pub fn checkpoint_every(mut self, bytes: u64) -> Self {
        self.checkpoint_every = bytes;
        self
    }

    /// Most sessions (and revocation tombstones) the auth engine holds at
    /// once (default 1,000,000; at most 4,294,967,295). Past it, issuing a
    /// session fails with [`Error::Busy`] until expired ones are reclaimed.
    /// Memory follows the sessions held, not this limit, so a high limit
    /// costs nothing until it is used; the limit keeps a flood of sign-ins
    /// from taking all of it.
    pub fn max_sessions(mut self, n: usize) -> Self {
        self.max_sessions = n.clamp(1, u32::MAX as usize);
        self
    }

    /// Report commits, errors, and security events to `observer`. See
    /// [`Observer`].
    pub fn observer(mut self, observer: impl Observer) -> Self {
        self.observers = Observers(Some(std::sync::Arc::new(observer)));
        self
    }

    /// Open (or create) the database.
    ///
    /// # Errors
    ///
    /// As [`open`](crate::open). [`Error::KeyUnavailable`] also when the key
    /// is not the one the database was created with.
    pub fn open(self) -> Result<Database> {
        Database::open_with(self)
    }
}

/// Most sessions (and revocation tombstones) the auth engine holds at once,
/// by default. Staging refuses a session past the limit; the session table
/// has room for twice as many, so a commit that was staged in time always
/// applies.
const DEFAULT_MAX_SESSIONS: usize = 1_000_000;

/// An open database.
///
/// `Database` is `Send` and `Sync`: share it between threads by reference or
/// behind an `Arc`. Dropping it writes the engines' buffered changes to their
/// own files (best effort; the commit log already holds them) and releases
/// the directory.
pub struct Database {
    inner: Arc<Inner>,
    /// True for the handle `open` returned. Other handles (the scheduler's)
    /// neither stop the scheduler nor checkpoint when dropped.
    owner: bool,
    /// Fires scheduled publishing; stopped when the owner is dropped.
    #[cfg(feature = "content")]
    scheduler: Option<crate::content::schedule::Scheduler>,
}

/// What every handle of one open database shares.
pub(crate) struct Inner {
    engines: Engines,
    core: Core,
    observers: Observers,
}

impl fmt::Debug for Database {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Database")
            .field("dir", &self.inner.core.dir())
            .field("visible", &self.inner.core.visible())
            .field("halted", &self.inner.core.halted())
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
        Database::builder(path).open()
    }

    /// A builder for opening the database in `path` with settings other than
    /// the defaults.
    pub fn builder(path: impl AsRef<Path>) -> Builder {
        Builder {
            dir: path.as_ref().to_path_buf(),
            keys: Keys::default(),
            checkpoint_every: CHECKPOINT_EVERY,
            max_sessions: DEFAULT_MAX_SESSIONS,
            observers: Observers::default(),
        }
    }

    fn open_with(builder: Builder) -> Result<Database> {
        let (core, new_database) = Core::open(&builder.dir)?;
        core.set_checkpoint_every(builder.checkpoint_every);
        let dir = core.dir().to_path_buf();
        let auth_dir = dir.join("auth");
        fs::create_dir(&auth_dir)?;
        // A build without the auth engine still checks the key, so the
        // database never opens under the wrong one.
        #[cfg_attr(not(feature = "auth"), allow(unused_variables))]
        let root = keys::root_key(&builder.keys, &auth_dir, new_database)?;

        let engines = Engines {
            #[cfg(feature = "auth")]
            auth: AuthEngine::open(
                &auth_dir.join("accounts"),
                &root,
                DEFAULT_REALM.id,
                builder.max_sessions,
            )?,
            #[cfg(feature = "content")]
            content: ContentEngine::open(&dir.join("content").join("store"), DEFAULT_SPACE.id)?,
        };

        core.recover(&engines, new_database, &[DEFAULT_REALM, DEFAULT_SPACE])?;
        for expected in [DEFAULT_REALM, DEFAULT_SPACE] {
            if core.catalog().collection(expected.id) != Some(expected) {
                return Err(Error::corrupt("the catalog (default collections)", 0));
            }
        }
        #[cfg_attr(not(feature = "content"), allow(unused_mut))]
        let mut db = Database {
            inner: Arc::new(Inner {
                engines,
                core,
                observers: builder.observers,
            }),
            owner: true,
            #[cfg(feature = "content")]
            scheduler: None,
        };
        #[cfg(feature = "content")]
        {
            db.scheduler = Some(crate::content::schedule::Scheduler::start(Arc::clone(
                &db.inner,
            ))?);
        }
        Ok(db)
    }

    /// Another handle of the database `inner` belongs to, for the database's
    /// own threads.
    #[cfg(feature = "content")]
    pub(crate) fn handle(inner: Arc<Inner>) -> Database {
        Database {
            inner,
            owner: false,
            scheduler: None,
        }
    }

    /// The directory the database lives in.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.inner.core.dir()
    }

    /// Whether the database serves writes: [`Health::ReadOnly`] after a
    /// failed write, until the process restarts.
    #[must_use]
    pub fn health(&self) -> Health {
        if self.inner.core.halted() {
            Health::ReadOnly {
                reason: "a write could not be made durable; restart to recover",
            }
        } else {
            Health::Ready
        }
    }

    #[cfg_attr(not(feature = "auth"), allow(dead_code))]
    pub(crate) fn observers(&self) -> &Observers {
        &self.inner.observers
    }

    /// The position of the last visible commit, to start a change feed
    /// from now.
    #[must_use]
    pub fn position(&self) -> Position {
        Position(self.inner.core.visible())
    }

    /// The changes committed after `from`, in order. See [`Feed`].
    ///
    /// # Errors
    ///
    /// [`Error::FeedBehind`] when `from` is older than the feed keeps (the
    /// changes of the last 65,536 commits that changed something, since
    /// the database was opened).
    pub fn feed(&self, from: Position) -> Result<Feed<'_>> {
        Feed::new(self, from)
    }

    pub(crate) fn feed_log(&self) -> &FeedLog {
        self.inner.core.feed()
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

    #[cfg(feature = "auth")]
    pub(crate) fn auth_engine(&self) -> &AuthEngine {
        &self.inner.engines.auth
    }

    #[cfg(feature = "content")]
    pub(crate) fn content_engine(&self) -> &ContentEngine {
        &self.inner.engines.content
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
        self.commit_as(false, &mut f)
    }

    /// Run `f` as one atomic commit, as [`commit`](Self::commit) does, and
    /// also check what it read: the commit conflicts (and `f` runs again)
    /// when an item `f` read was changed by a commit after its snapshot.
    /// The result is as if the commits ran one after another. Checked are
    /// the items read by key: entities, routes, the space's types and
    /// settings, references to an entity, accounts, identifiers, sessions,
    /// and the roles policy. Listings and other index reads are not.
    ///
    /// ```no_run
    /// # #[cfg(feature = "content")]
    /// # fn main() -> nex_db::Result<()> {
    /// use nex_db::{Entity, Patch};
    /// let db = nex_db::open("data/site")?;
    /// # let (from, to) = (nex_db::Rid::from_bytes([1; 16]), nex_db::Rid::from_bytes([2; 16]));
    /// // Move one seat from `from` to `to`, reading both first.
    /// db.commit_serializable(|tx| {
    ///     let seats = |e: Option<nex_db::Entry>| e.and_then(|e| e.field("seats")?.as_int()).unwrap_or(0);
    ///     let (a, b) = (seats(tx.content().draft(from)?), seats(tx.content().draft(to)?));
    ///     tx.content().save_draft(from, Patch::new().set("seats", a - 1))?;
    ///     tx.content().save_draft(to, Patch::new().set("seats", b + 1))
    /// })?;
    /// # Ok(())
    /// # }
    /// # #[cfg(not(feature = "content"))]
    /// # fn main() {}
    /// ```
    ///
    /// # Errors
    ///
    /// As [`commit`](Self::commit).
    pub fn commit_serializable<T, F>(&self, mut f: F) -> Result<T>
    where
        F: FnMut(&mut Transaction<'_>) -> Result<T>,
    {
        self.commit_as(true, &mut f)
    }

    fn commit_as<T, F>(&self, serializable: bool, f: &mut F) -> Result<T>
    where
        F: FnMut(&mut Transaction<'_>) -> Result<T>,
    {
        let started = std::time::Instant::now();
        let result = self.commit_attempts(f, started, serializable);
        if let Err(err) = &result {
            self.inner.observers.error(err);
        }
        result
    }

    fn commit_attempts<T, F>(
        &self,
        f: &mut F,
        started: std::time::Instant,
        serializable: bool,
    ) -> Result<T>
    where
        F: FnMut(&mut Transaction<'_>) -> Result<T>,
    {
        for attempt in 1..=ATTEMPTS {
            let snapshot = self.inner.core.snapshot();
            let mut tx = Transaction::new(self, snapshot.seq(), serializable);
            let value = f(&mut tx)?;
            match self
                .inner
                .core
                .commit(&self.inner.engines, &snapshot, &tx.staged())
            {
                Ok(seq) => {
                    if let Some(seq) = seq {
                        self.inner.observers.commit(&CommitInfo {
                            position: Position(seq),
                            attempts: attempt as u32,
                            took: started.elapsed(),
                        });
                    }
                    return Ok(value);
                }
                Err(Attempt::Conflict) => {
                    drop(snapshot);
                    self.inner.core.wait_for_sequenced();
                }
                Err(Attempt::Failed(err)) => return Err(err),
            }
        }
        Err(Error::Conflict)
    }
}

impl Database {
    /// Run `f` with reads that all see one snapshot: every engine as of the
    /// same commit, whatever commits while `f` runs.
    ///
    /// ```
    /// # #[cfg(all(feature = "auth", feature = "content"))]
    /// # fn main() -> nex_db::Result<()> {
    /// # let dir = std::env::temp_dir().join(format!("nex-db-read-doc-{}", std::process::id()));
    /// # let _ = std::fs::remove_dir_all(&dir);
    /// let db = nex_db::open(&dir)?;
    /// let rid = db.content().create(nex_db::Entity::new("page").path("/a"))?;
    /// let (route, page) = db.read(|r| {
    ///     let route = r.content().resolve(nex_db::DEFAULT_SITE, "/a")?;
    ///     Ok((route, r.content().get(rid)?))
    /// })?;
    /// assert_eq!(route.map(|r| r.entity()), page.map(|p| p.rid()));
    /// # drop(db);
    /// # std::fs::remove_dir_all(&dir).unwrap();
    /// # Ok(())
    /// # }
    /// # #[cfg(not(all(feature = "auth", feature = "content")))]
    /// # fn main() {}
    /// ```
    ///
    /// A snapshot may run for 60 seconds; reads after that fail with
    /// [`Error::SnapshotTooOld`]. Sessions are the exception to the
    /// snapshot: a revoked session is revoked for every reader at once.
    ///
    /// # Errors
    ///
    /// Any error `f` returns, unchanged.
    pub fn read<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Read<'_>) -> Result<T>,
    {
        let read = Read {
            db: self,
            snapshot: self.inner.core.snapshot(),
        };
        f(&read)
    }
}

/// Reads at one snapshot, handed to the closure of [`Database::read`].
pub struct Read<'db> {
    #[cfg_attr(not(any(feature = "auth", feature = "content")), allow(dead_code))]
    db: &'db Database,
    snapshot: SnapshotGuard<'db>,
}

impl fmt::Debug for Read<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Read")
            .field("snapshot", &self.snapshot.seq())
            .finish_non_exhaustive()
    }
}

impl Read<'_> {
    /// Auth reads at this snapshot.
    #[cfg(feature = "auth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "auth")))]
    #[must_use]
    pub fn auth(&self) -> AuthRead<'_> {
        AuthRead {
            engine: self.db.auth_engine(),
            snapshot: &self.snapshot,
        }
    }

    /// Content reads at this snapshot.
    #[cfg(feature = "content")]
    #[cfg_attr(docsrs, doc(cfg(feature = "content")))]
    #[must_use]
    pub fn content(&self) -> ContentRead<'_> {
        ContentRead {
            engine: self.db.content_engine(),
            snapshot: &self.snapshot,
        }
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        if !self.owner {
            return;
        }
        #[cfg(feature = "content")]
        if let Some(scheduler) = self.scheduler.take() {
            scheduler.stop();
        }
        // Best effort: the log holds every commit, so a failure here only
        // means a longer replay at the next open.
        let _ = self.inner.core.checkpoint(&self.inner.engines, false);
    }
}

impl Inner {
    #[cfg(feature = "content")]
    pub(crate) fn content_engine(&self) -> &ContentEngine {
        &self.engines.content
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
    /// What the closure reads is checked too.
    #[cfg_attr(not(any(feature = "auth", feature = "content")), allow(dead_code))]
    serializable: bool,
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
    fn new(db: &'db Database, snapshot: Seq, serializable: bool) -> Self {
        Transaction {
            db,
            snapshot,
            serializable,
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
        let serializable = self.serializable;
        AuthTx {
            staged: self.auth.get_or_insert_with(|| {
                AuthStaged::new(db.auth_engine()).serializable(serializable)
            }),
        }
    }

    /// Content operations in this transaction.
    #[cfg(feature = "content")]
    #[cfg_attr(docsrs, doc(cfg(feature = "content")))]
    pub fn content(&mut self) -> ContentTx<'_, 'db> {
        let db = self.db;
        let serializable = self.serializable;
        ContentTx {
            staged: self.content.get_or_insert_with(|| {
                ContentStaged::new(db.content_engine()).serializable(serializable)
            }),
        }
    }

    /// Every engine's staged work, for the core.
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
        staged
    }
}
