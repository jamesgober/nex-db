//! The database facade: open, the engines it hosts, transactions.
//!
//! The commit pipeline, recovery, and the catalog live in
//! [`Core`](crate::core::pipeline::Core); this module holds the typed engines
//! and hands them to the core through the [`Registry`] contract.

use std::{fmt, path::Path};

#[cfg(feature = "auth")]
use crate::auth::{Auth, AuthEngine, AuthStaged, AuthTx};
#[cfg(feature = "content")]
use crate::content::{Content, ContentEngine, ContentStaged, ContentTx};
use crate::{
    core::{
        catalog::{DEFAULT_REALM, DEFAULT_SPACE},
        fs, keys,
        pipeline::{ATTEMPTS, Attempt, Core},
        record::Seq,
    },
    engine::{Engine, EngineId, Registry, Staged},
    error::{Error, Result},
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

/// An open database.
///
/// `Database` is `Send` and `Sync`: share it between threads by reference or
/// behind an `Arc`. Dropping it writes the engines' buffered changes to their
/// own files (best effort; the commit log already holds them) and releases
/// the directory.
pub struct Database {
    engines: Engines,
    core: Core,
}

impl fmt::Debug for Database {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Database")
            .field("dir", &self.core.dir())
            .field("visible", &self.core.visible())
            .field("halted", &self.core.halted())
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
        let (core, new_database) = Core::open(path.as_ref())?;
        let dir = core.dir().to_path_buf();
        let auth_dir = dir.join("auth");
        fs::create_dir(&auth_dir)?;
        if new_database {
            keys::create_if_missing(&auth_dir)?;
        }

        let engines = Engines {
            #[cfg(feature = "auth")]
            auth: {
                let root = keys::load(&auth_dir)?;
                AuthEngine::open(&auth_dir.join("accounts"), &root, DEFAULT_REALM.id)?
            },
            #[cfg(feature = "content")]
            content: ContentEngine::open(&dir.join("content").join("store"), DEFAULT_SPACE.id)?,
        };

        core.recover(&engines, new_database, &[DEFAULT_REALM, DEFAULT_SPACE])?;
        for expected in [DEFAULT_REALM, DEFAULT_SPACE] {
            if core.catalog().collection(expected.id) != Some(expected) {
                return Err(Error::corrupt("the catalog (default collections)", 0));
            }
        }
        Ok(Database { engines, core })
    }

    /// The directory the database lives in.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.core.dir()
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
        &self.engines.auth
    }

    #[cfg(feature = "content")]
    pub(crate) fn content_engine(&self) -> &ContentEngine {
        &self.engines.content
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
            let snapshot = self.core.snapshot();
            let mut tx = Transaction::new(self, snapshot.seq());
            let value = f(&mut tx)?;
            match self
                .core
                .commit(&self.engines, snapshot.seq(), &tx.staged())
            {
                Ok(()) => return Ok(value),
                Err(Attempt::Conflict) => {}
                Err(Attempt::Failed(err)) => return Err(err),
            }
        }
        Err(Error::Conflict)
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        // Best effort: the log holds every commit, so a failure here only
        // means a longer replay at the next open.
        self.core.checkpoint(&self.engines);
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
            staged: self
                .auth
                .get_or_insert_with(|| AuthStaged::new(db.auth_engine())),
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
                .get_or_insert_with(|| ContentStaged::new(db.content_engine())),
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
