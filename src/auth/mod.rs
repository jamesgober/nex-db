//! The auth engine: accounts, password hashing, sessions.
//!
//! Accounts, identifiers, and credentials live in an lsm-db store in
//! `auth/accounts/` (its own write-ahead log is off: the commit log is the
//! write-ahead log). Sessions live in memory in the session table and are
//! rebuilt from the commit log at open. Tokens and identifiers are stored only
//! as keyed BLAKE3 digests; passwords only as Argon2id hashes, checked inside
//! the engine.
//!
//! There is no query, scan, list, or export of credentials, session digests,
//! or identifiers. The operations below are the whole surface.

mod sessions;
pub(crate) mod token;
pub(crate) mod types;

use std::{
    collections::HashSet,
    fmt,
    path::Path,
    sync::{
        OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

use crypt_io::{Zeroizing, kdf, mac};
use lsm_db::{Batch, Lsm};

use self::{
    sessions::{SessionTable, Slot},
    token::Token,
    types::{HashedPassword, RevokeReason, Session, SessionSpec, SignIn, Validation},
};
use crate::{
    Database,
    core::{
        codec::{Reader, Writer},
        conflict::ConflictTable,
        keys::RootKey,
        now_ms,
        record::Seq,
    },
    engine::{Conflict, Engine, EngineId, Staged},
    error::{Error, Result},
    ids::AccountId,
};

/// Section format version.
const FORMAT: u16 = 1;

const OP_CREATE_ACCOUNT: u8 = 1;
const OP_ISSUE_SESSION: u8 = 2;
const OP_REVOKE_SESSION: u8 = 3;

/// Longest identifier (an email address), in bytes.
const MAX_IDENTIFIER: usize = 320;

/// Longest password, in bytes. Bounds the work one sign-in can demand.
const MAX_PASSWORD: usize = 1024;

/// Most sessions (and revocation tombstones) held at once.
const MAX_SESSIONS: usize = 1_000_000;

/// Key of the account store's applied-through mark.
const META_APPLIED: &[u8] = b"\0meta/applied";

/// Account record format.
const ACCOUNT_FORMAT: u8 = 1;

/// Standing of a new account. Standing changes arrive in 0.3.
const STANDING_ACTIVE: u8 = 1;

/// Credential kind: an Argon2id password hash.
const CREDENTIAL_PASSWORD: u8 = 1;

/// Key labels for the keys derived from the root key.
const TOKEN_KEY_LABEL: &[u8] = b"nex-db 2026 auth token digest";
const IDENTIFIER_KEY_LABEL: &[u8] = b"nex-db 2026 auth identifier digest";

fn store_key(collection: u32, tag: u8, id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(5 + id.len());
    key.extend_from_slice(&collection.to_be_bytes());
    key.push(tag);
    key.extend_from_slice(id);
    key
}

fn account_key(collection: u32, account: AccountId) -> Vec<u8> {
    store_key(collection, b'a', account.as_bytes())
}

fn identifier_key(collection: u32, digest: &[u8; 32]) -> Vec<u8> {
    store_key(collection, b'i', digest)
}

fn credential_key(collection: u32, account: AccountId) -> Vec<u8> {
    store_key(collection, b'c', account.as_bytes())
}

/// Conflict-table key for a session digest.
fn session_key(digest: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(b's');
    key.extend_from_slice(digest);
    key
}

/// Trim, check, and lower-case an identifier.
fn normalize_identifier(identifier: &str) -> Result<String> {
    let trimmed = identifier.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_IDENTIFIER {
        return Err(Error::invalid("identifier", "must be 1 to 320 bytes"));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(Error::invalid("identifier", "contains a control character"));
    }
    Ok(trimmed.to_lowercase())
}

fn check_password(password: &str) -> Result<()> {
    if password.is_empty() || password.len() > MAX_PASSWORD {
        return Err(Error::invalid("password", "must be 1 to 1024 bytes"));
    }
    Ok(())
}

/// The auth engine.
pub(crate) struct AuthEngine {
    collection: u32,
    token_key: Zeroizing<[u8; 32]>,
    identifier_key: Zeroizing<[u8; 32]>,
    accounts: Lsm,
    /// Highest seq whose account changes the account store holds.
    applied: AtomicU64,
    sessions: SessionTable,
    conflicts: ConflictTable,
    /// Password hashes in progress, bounded by `max_hashing`.
    hashing: AtomicUsize,
    max_hashing: usize,
    /// A hash checked for unknown identifiers, so they cost what a wrong
    /// password costs.
    dummy: OnceLock<String>,
}

impl fmt::Debug for AuthEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthEngine")
            .field("collection", &self.collection)
            .field("applied", &self.applied.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl AuthEngine {
    /// Open the engine's store in `dir`.
    pub(crate) fn open(dir: &Path, root: &RootKey, collection: u32) -> Result<Self> {
        let accounts = Lsm::open(dir)?;
        let applied = match accounts.get(META_APPLIED)? {
            Some(bytes) => {
                let bytes: [u8; 8] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::corrupt("the account store mark", 0))?;
                u64::from_le_bytes(bytes)
            }
            None => 0,
        };
        let max_hashing = std::thread::available_parallelism().map_or(1, usize::from);
        Ok(AuthEngine {
            collection,
            token_key: root.derive(TOKEN_KEY_LABEL),
            identifier_key: root.derive(IDENTIFIER_KEY_LABEL),
            accounts,
            applied: AtomicU64::new(applied),
            sessions: SessionTable::new(),
            conflicts: ConflictTable::new(),
            hashing: AtomicUsize::new(0),
            max_hashing,
            dummy: OnceLock::new(),
        })
    }

    fn token_digest(&self, random: &[u8; 32]) -> [u8; 32] {
        mac::blake3_keyed(&self.token_key, random)
    }

    fn identifier_digest(&self, normalized: &str) -> [u8; 32] {
        mac::blake3_keyed(&self.identifier_key, normalized.as_bytes())
    }

    fn account_exists(&self, account: AccountId) -> Result<bool> {
        Ok(self
            .accounts
            .get(account_key(self.collection, account))?
            .is_some())
    }

    fn account_for(&self, digest: &[u8; 32]) -> Result<Option<AccountId>> {
        match self.accounts.get(identifier_key(self.collection, digest))? {
            Some(bytes) => {
                let bytes: [u8; 16] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::corrupt("an identifier record", 0))?;
                Ok(Some(AccountId::from_bytes(bytes)))
            }
            None => Ok(None),
        }
    }

    fn password_hash(&self, account: AccountId) -> Result<Option<Zeroizing<String>>> {
        let Some(bytes) = self
            .accounts
            .get(credential_key(self.collection, account))?
        else {
            return Ok(None);
        };
        let bytes = Zeroizing::new(bytes);
        let mut r = Reader::new(&bytes, "a credential record", 0);
        if r.u8()? != CREDENTIAL_PASSWORD {
            return Err(Error::corrupt("a credential record", 0));
        }
        let phc = Zeroizing::new(r.str16()?.to_owned());
        r.finish()?;
        Ok(Some(phc))
    }

    /// Take a password-hashing slot, or fail with [`Error::Busy`].
    fn hashing_slot(&self) -> Result<HashingSlot<'_>> {
        let previous = self.hashing.fetch_add(1, Ordering::AcqRel);
        let slot = HashingSlot(&self.hashing);
        if previous >= self.max_hashing {
            return Err(Error::Busy {
                what: "password hashing",
            });
        }
        Ok(slot)
    }

    fn validate(&self, token: &str) -> Validation {
        let Some(random) = token::parse(token) else {
            return Validation::Malformed;
        };
        let digest = self.token_digest(&random);
        match self.sessions.get(&digest) {
            None => Validation::Unknown,
            Some(Slot::Revoked(reason)) => Validation::Revoked { reason },
            Some(Slot::Live(session)) if now_ms() >= session.expires_ms => Validation::Expired,
            Some(Slot::Live(session)) => Validation::Valid(session),
        }
    }

    fn hash_password(&self, password: &str) -> Result<HashedPassword> {
        check_password(password)?;
        let _slot = self.hashing_slot()?;
        let phc = kdf::argon2_hash(password.as_bytes())
            .map_err(|_| Error::invalid("password", "could not be hashed"))?;
        Ok(HashedPassword(phc))
    }

    /// Check `password` for `identifier`. Unknown identifiers cost one
    /// Argon2id check, like a wrong password.
    fn verify_password(&self, identifier: &str, password: &str) -> Result<Option<AccountId>> {
        check_password(password)?;
        let found = match normalize_identifier(identifier) {
            Ok(normalized) => match self.account_for(&self.identifier_digest(&normalized))? {
                Some(account) => self.password_hash(account)?.map(|phc| (account, phc)),
                None => None,
            },
            Err(_) => None,
        };
        let _slot = self.hashing_slot()?;
        // Built before the lookup result is used, so the first sign-in of a
        // process costs the same extra hash whether the identifier exists or
        // not.
        let dummy = self.dummy_hash()?;
        match found {
            Some((account, phc)) => match kdf::argon2_check(&phc, password.as_bytes()) {
                Ok(()) => Ok(Some(account)),
                Err(crypt_io::Error::AuthenticationFailed) => Ok(None),
                Err(_) => Err(Error::corrupt("a stored password hash", 0)),
            },
            None => {
                let _ = kdf::argon2_check(dummy, password.as_bytes());
                Ok(None)
            }
        }
    }

    fn dummy_hash(&self) -> Result<&str> {
        if let Some(hash) = self.dummy.get() {
            return Ok(hash);
        }
        let random =
            crypt_io::generate_key().map_err(|e| Error::storage("drawing random bytes", e))?;
        let hash = kdf::argon2_hash(&random[..])
            .map_err(|_| Error::invalid("password", "could not be hashed"))?;
        Ok(self.dummy.get_or_init(|| hash))
    }
}

/// A held password-hashing slot.
struct HashingSlot<'a>(&'a AtomicUsize);

impl Drop for HashingSlot<'_> {
    fn drop(&mut self) {
        let _ = self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// One decoded auth operation, borrowing the section bytes.
enum Op<'a> {
    CreateAccount {
        account: AccountId,
        digest: [u8; 32],
        created_ms: u64,
        phc: &'a str,
    },
    IssueSession {
        digest: [u8; 32],
        session: Session,
    },
    RevokeSession {
        digest: [u8; 32],
        reason: RevokeReason,
    },
}

fn decode_ops(seq: Seq, body: &[u8]) -> Result<Vec<Op<'_>>> {
    let mut r = Reader::new(body, "an auth section", seq);
    let mut ops = Vec::new();
    while !r.is_empty() {
        let op = match r.u8()? {
            OP_CREATE_ACCOUNT => Op::CreateAccount {
                account: AccountId::from_bytes(r.fixed()?),
                digest: r.fixed()?,
                created_ms: r.u64()?,
                phc: r.str16()?,
            },
            OP_ISSUE_SESSION => {
                let digest = r.fixed()?;
                let account = AccountId::from_bytes(r.fixed()?);
                let created_ms = r.u64()?;
                let expires_ms = r.u64()?;
                Op::IssueSession {
                    digest,
                    session: Session {
                        account,
                        created_ms,
                        expires_ms,
                    },
                }
            }
            OP_REVOKE_SESSION => {
                let digest = r.fixed()?;
                let reason = match r.u8()? {
                    1 => RevokeReason::Revoked,
                    _ => return Err(Error::corrupt("an auth revoke reason", seq)),
                };
                let _at_ms = r.u64()?;
                Op::RevokeSession { digest, reason }
            }
            _ => return Err(Error::corrupt("an auth operation", seq)),
        };
        ops.push(op);
    }
    Ok(ops)
}

impl Engine for AuthEngine {
    fn id(&self) -> EngineId {
        EngineId::AUTH
    }

    fn name(&self) -> &'static str {
        "auth"
    }

    fn format(&self) -> u16 {
        FORMAT
    }

    fn define(&self, definition: &[u8]) -> Result<()> {
        // Realm policies (lockout, session limits) arrive with 0.3; until
        // then a realm has no definition.
        if definition.is_empty() {
            Ok(())
        } else {
            Err(Error::invalid(
                "realm definition",
                "must be empty in this version",
            ))
        }
    }

    fn apply(&self, seq: Seq, collection: u32, format: u16, body: &[u8]) -> Result<()> {
        if format != FORMAT || collection != self.collection {
            return Err(Error::corrupt("an auth section header", seq));
        }
        let ops = decode_ops(seq, body)?;

        // Account changes: one batch with the applied mark, skipped when the
        // store already holds this seq.
        if seq > self.applied.load(Ordering::Acquire) {
            let mut batch = Batch::new();
            for op in &ops {
                if let Op::CreateAccount {
                    account,
                    digest,
                    created_ms,
                    phc,
                } = op
                {
                    let mut record = Vec::with_capacity(46);
                    let mut w = Writer::new(&mut record);
                    w.u8(ACCOUNT_FORMAT);
                    w.u64(*created_ms);
                    w.bytes(digest);
                    w.u8(STANDING_ACTIVE);
                    w.u32(0);
                    batch.put(account_key(self.collection, *account), record);
                    batch.put(identifier_key(self.collection, digest), account.as_bytes());
                    let mut credential = Zeroizing::new(Vec::with_capacity(3 + phc.len()));
                    let mut w = Writer::new(&mut credential);
                    w.u8(CREDENTIAL_PASSWORD);
                    w.str16(phc)?;
                    batch.put(credential_key(self.collection, *account), &credential[..]);
                }
            }
            if !batch.is_empty() {
                batch.put(META_APPLIED, seq.to_le_bytes());
                self.accounts.write(batch)?;
                self.applied.store(seq, Ordering::Release);
            }
        }

        // Sessions live in memory and are rebuilt from the whole log.
        for op in ops {
            match op {
                Op::IssueSession { digest, session } => self.sessions.insert(digest, session),
                Op::RevokeSession { digest, reason } => self.sessions.revoke(digest, reason),
                Op::CreateAccount { .. } => {}
            }
        }
        Ok(())
    }

    fn durable_through(&self) -> Seq {
        // The session table has no checkpoint in this version, so recovery
        // replays the auth sections of the whole log. Account changes the
        // store already holds are skipped by `apply`.
        0
    }

    fn checkpoint(&self) -> Result<Seq> {
        self.accounts.flush()?;
        Ok(self.durable_through())
    }

    fn reclaim(&self, watermark: Seq) {
        self.conflicts.prune(watermark);
    }
}

/// An auth operation staged in a transaction.
enum StagedOp {
    CreateAccount {
        account: AccountId,
        digest: [u8; 32],
        created_ms: u64,
        phc: Zeroizing<String>,
    },
    IssueSession {
        digest: [u8; 32],
        account: AccountId,
        created_ms: u64,
        expires_ms: u64,
    },
    RevokeSession {
        digest: [u8; 32],
        at_ms: u64,
    },
}

/// One transaction's auth work.
pub(crate) struct AuthStaged<'e> {
    engine: &'e AuthEngine,
    ops: Vec<StagedOp>,
    /// Conflict-table keys this work writes.
    writes: Vec<Vec<u8>>,
    identifiers: HashSet<[u8; 32]>,
    accounts: HashSet<AccountId>,
    issued: HashSet<[u8; 32]>,
}

impl<'e> AuthStaged<'e> {
    pub(crate) fn new(engine: &'e AuthEngine) -> Self {
        AuthStaged {
            engine,
            ops: Vec::new(),
            writes: Vec::new(),
            identifiers: HashSet::new(),
            accounts: HashSet::new(),
            issued: HashSet::new(),
        }
    }
}

impl Staged for AuthStaged<'_> {
    fn engine(&self) -> EngineId {
        EngineId::AUTH
    }

    fn collection(&self) -> u32 {
        self.engine.collection
    }

    fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// A revocation takes effect ahead of ordinary commits.
    fn priority(&self) -> bool {
        self.ops
            .iter()
            .any(|op| matches!(op, StagedOp::RevokeSession { .. }))
    }

    fn validate(&self, snapshot: Seq) -> std::result::Result<(), Conflict> {
        if self
            .engine
            .conflicts
            .conflicts(self.writes.iter().map(Vec::as_slice), snapshot)
        {
            Err(Conflict)
        } else {
            Ok(())
        }
    }

    fn reserve(&self, seq: Seq) {
        self.engine
            .conflicts
            .record(self.writes.iter().map(Vec::as_slice), seq);
    }

    fn encode(&self, _seq: Seq, out: &mut Vec<u8>) -> Result<()> {
        let mut w = Writer::new(out);
        for op in &self.ops {
            match op {
                StagedOp::CreateAccount {
                    account,
                    digest,
                    created_ms,
                    phc,
                } => {
                    w.u8(OP_CREATE_ACCOUNT);
                    w.bytes(account.as_bytes());
                    w.bytes(digest);
                    w.u64(*created_ms);
                    w.str16(phc)?;
                }
                StagedOp::IssueSession {
                    digest,
                    account,
                    created_ms,
                    expires_ms,
                } => {
                    w.u8(OP_ISSUE_SESSION);
                    w.bytes(digest);
                    w.bytes(account.as_bytes());
                    w.u64(*created_ms);
                    w.u64(*expires_ms);
                }
                StagedOp::RevokeSession { digest, at_ms } => {
                    w.u8(OP_REVOKE_SESSION);
                    w.bytes(digest);
                    w.u8(1);
                    w.u64(*at_ms);
                }
            }
        }
        Ok(())
    }
}

/// Auth operations inside a [`Transaction`](crate::Transaction).
///
/// Returned by [`Transaction::auth`](crate::Transaction::auth). Nothing is
/// written until the transaction commits; if the closure returns an error,
/// nothing is written at all.
pub struct AuthTx<'t, 'db> {
    pub(crate) staged: &'t mut AuthStaged<'db>,
}

impl fmt::Debug for AuthTx<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthTx")
            .field("operations", &self.staged.ops.len())
            .finish()
    }
}

impl AuthTx<'_, '_> {
    /// Create an account for `identifier` (an email address or a user name)
    /// with a password hashed by [`Auth::hash_password`].
    ///
    /// The identifier is trimmed and lower-cased; it is stored only as a
    /// keyed digest, so it cannot be read back or listed.
    ///
    /// ```no_run
    /// # fn main() -> nex_db::Result<()> {
    /// let db = nex_db::open("data/site")?;
    /// let password = db.auth().hash_password("correct horse battery staple")?;
    /// let account = db.commit(|tx| tx.auth().create_account("ann@example.com", &password))?;
    /// # let _ = account;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] (`what = "identifier"`) when an account
    ///   already uses the identifier.
    /// - [`Error::Invalid`] when the identifier is empty, longer than 320
    ///   bytes, or holds a control character.
    pub fn create_account(
        &mut self,
        identifier: &str,
        password: &HashedPassword,
    ) -> Result<AccountId> {
        let engine = self.staged.engine;
        let normalized = normalize_identifier(identifier)?;
        let digest = engine.identifier_digest(&normalized);
        if self.staged.identifiers.contains(&digest) || engine.account_for(&digest)?.is_some() {
            return Err(Error::AlreadyExists { what: "identifier" });
        }
        let account = AccountId::generate();
        let _ = self.staged.identifiers.insert(digest);
        let _ = self.staged.accounts.insert(account);
        self.staged
            .writes
            .push(identifier_key(engine.collection, &digest));
        self.staged
            .writes
            .push(account_key(engine.collection, account));
        self.staged.ops.push(StagedOp::CreateAccount {
            account,
            digest,
            created_ms: now_ms(),
            phc: Zeroizing::new(password.0.clone()),
        });
        Ok(account)
    }

    /// Issue a session for `account` and return its token. The token is
    /// returned once; nex-db keeps only its digest.
    ///
    /// # Errors
    ///
    /// - [`Error::Invalid`] when the account does not exist.
    /// - [`Error::Busy`] when the session table is full.
    pub fn issue_session(&mut self, account: AccountId, spec: SessionSpec) -> Result<Token> {
        let engine = self.staged.engine;
        if !self.staged.accounts.contains(&account) && !engine.account_exists(account)? {
            return Err(Error::invalid("account", "no such account"));
        }
        if engine.sessions.len() + self.staged.issued.len() >= MAX_SESSIONS {
            return Err(Error::Busy {
                what: "the session table",
            });
        }
        let (token, random) = Token::generate()?;
        let digest = engine.token_digest(&random);
        let created_ms = now_ms();
        let _ = self.staged.issued.insert(digest);
        self.staged.writes.push(session_key(&digest));
        self.staged.ops.push(StagedOp::IssueSession {
            digest,
            account,
            created_ms,
            expires_ms: created_ms.saturating_add(spec.ttl_ms()),
        });
        Ok(token)
    }

    /// Revoke the session `token` names. Returns `true` when a session was
    /// revoked, `false` when the token names no session or one already
    /// revoked. A revoked session never validates again.
    ///
    /// # Errors
    ///
    /// Only storage errors; a malformed token returns `Ok(false)`.
    pub fn revoke(&mut self, token: impl AsRef<str>) -> Result<bool> {
        let engine = self.staged.engine;
        let Some(random) = token::parse(token.as_ref()) else {
            return Ok(false);
        };
        let digest = engine.token_digest(&random);
        let live = matches!(engine.sessions.get(&digest), Some(Slot::Live(_)))
            || self.staged.issued.contains(&digest);
        if !live {
            return Ok(false);
        }
        self.staged.writes.push(session_key(&digest));
        self.staged.ops.push(StagedOp::RevokeSession {
            digest,
            at_ms: now_ms(),
        });
        Ok(true)
    }
}

/// The auth engine's operations outside a transaction.
///
/// Returned by [`Database::auth`]. Each writing call here is its own commit;
/// to write auth and content together, use
/// [`Database::commit`](crate::Database::commit) and
/// [`Transaction::auth`](crate::Transaction::auth).
#[derive(Debug, Clone, Copy)]
pub struct Auth<'db> {
    pub(crate) db: &'db Database,
}

impl Auth<'_> {
    fn engine(&self) -> &AuthEngine {
        self.db.auth_engine()
    }

    /// Check a session token. Reads memory only and allocates nothing.
    ///
    /// ```no_run
    /// # fn main() -> nex_db::Result<()> {
    /// let db = nex_db::open("data/site")?;
    /// # let cookie = "";
    /// match db.auth().validate(cookie)? {
    ///     nex_db::Validation::Valid(session) => println!("account {}", session.account()),
    ///     _ => println!("guest"),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// None in this version; the `Result` leaves room for split-process
    /// auth, where validation crosses a channel.
    pub fn validate(&self, token: impl AsRef<str>) -> Result<Validation> {
        Ok(self.engine().validate(token.as_ref()))
    }

    /// Hash a password with Argon2id (19 MiB, 2 passes, 1 lane, random
    /// salt). Takes tens of milliseconds by design. Call it before
    /// [`Database::commit`], never inside the closure.
    ///
    /// # Errors
    ///
    /// - [`Error::Invalid`] when the password is empty or longer than 1024
    ///   bytes.
    /// - [`Error::Busy`] when as many hashes as the machine has cores are
    ///   already running.
    pub fn hash_password(&self, password: &str) -> Result<HashedPassword> {
        self.engine().hash_password(password)
    }

    /// Create an account in its own commit. See [`AuthTx::create_account`].
    ///
    /// # Errors
    ///
    /// As [`AuthTx::create_account`], plus the errors of
    /// [`Database::commit`].
    pub fn create_account(&self, identifier: &str, password: &HashedPassword) -> Result<AccountId> {
        self.db
            .commit(|tx| tx.auth().create_account(identifier, password))
    }

    /// Issue a session in its own commit. See [`AuthTx::issue_session`].
    ///
    /// # Errors
    ///
    /// As [`AuthTx::issue_session`], plus the errors of
    /// [`Database::commit`].
    pub fn issue_session(&self, account: AccountId, spec: SessionSpec) -> Result<Token> {
        self.db.commit(|tx| tx.auth().issue_session(account, spec))
    }

    /// Revoke a session in its own commit. See [`AuthTx::revoke`].
    ///
    /// # Errors
    ///
    /// The errors of [`Database::commit`].
    pub fn revoke(&self, token: impl AsRef<str>) -> Result<bool> {
        let token = token.as_ref();
        self.db.commit(|tx| tx.auth().revoke(token))
    }

    /// Check `password` for `identifier` inside the engine and, when it
    /// matches, issue a session. The password hash never leaves the engine.
    ///
    /// ```no_run
    /// # fn main() -> nex_db::Result<()> {
    /// let db = nex_db::open("data/site")?;
    /// match db.auth().sign_in("ann@example.com", "correct horse battery staple", nex_db::SessionSpec::web())? {
    ///     nex_db::SignIn::Success { token, .. } => println!("cookie {}", token.as_str().len()),
    ///     _ => println!("wrong identifier or password"),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// - [`Error::Invalid`] when the password is empty or longer than 1024
    ///   bytes.
    /// - [`Error::Busy`] when the hashing slots are full.
    /// - The errors of [`Database::commit`] when issuing the session.
    pub fn sign_in(&self, identifier: &str, password: &str, spec: SessionSpec) -> Result<SignIn> {
        match self.engine().verify_password(identifier, password)? {
            Some(account) => {
                let token = self.issue_session(account, spec)?;
                Ok(SignIn::Success { account, token })
            }
            None => Ok(SignIn::Failed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_identifier_trims_and_lowercases() {
        assert_eq!(
            normalize_identifier("  Ann@Example.COM ").unwrap(),
            "ann@example.com"
        );
    }

    #[test]
    fn test_normalize_identifier_rejects_empty_long_and_control() {
        assert!(normalize_identifier("   ").is_err());
        assert!(normalize_identifier(&"a".repeat(MAX_IDENTIFIER + 1)).is_err());
        assert!(normalize_identifier("a\u{0}b").is_err());
    }

    #[test]
    fn test_check_password_bounds() {
        assert!(check_password("").is_err());
        assert!(check_password(&"p".repeat(MAX_PASSWORD + 1)).is_err());
        assert!(check_password("p").is_ok());
    }

    #[test]
    fn test_decode_ops_unknown_op_is_corrupt() {
        assert!(matches!(
            decode_ops(1, &[9]),
            Err(Error::Corrupt { at: 1, .. })
        ));
    }

    #[test]
    fn test_decode_ops_truncated_is_corrupt() {
        assert!(decode_ops(1, &[OP_ISSUE_SESSION, 0, 0]).is_err());
    }

    #[test]
    fn test_store_keys_are_distinct_per_kind() {
        let account = AccountId::from_bytes([3; 16]);
        assert_ne!(account_key(1, account), credential_key(1, account));
        assert_ne!(account_key(1, account), account_key(2, account));
        assert!(!identifier_key(1, &[0; 32]).starts_with(META_APPLIED));
    }
}
