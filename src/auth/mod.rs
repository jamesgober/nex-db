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
    collections::{HashMap, HashSet},
    fmt,
    path::Path,
    sync::{
        Mutex, OnceLock, PoisonError,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::SystemTime,
};

use crypt_io::{Crypt, Zeroizing, kdf, mac};
use lsm_db::{Batch, Lsm};

use self::{
    sessions::{EpochTable, SessionTable, Slot},
    token::Token,
    types::{
        HashedPassword, Login, RevokeReason, Session, SessionSpec, SignIn, Standing, Validation,
        ms_of, time_of,
    },
};
use crate::{
    Database,
    core::{
        codec::{Reader, Writer},
        conflict::ConflictTable,
        keys::RootKey,
        now_ms,
        pipeline::SnapshotGuard,
        record::{SEALED, Section, Seq},
        versions::Versions,
    },
    engine::{Conflict, Engine, EngineId, Staged},
    error::{Error, Result},
    ids::AccountId,
};

/// Section format 1: the operations in plain form (0.1 and 0.2 logs). Read,
/// never written.
const FORMAT_PLAIN: u16 = 1;

/// Section format 2, written from 0.3: the operations padded and encrypted
/// (see [`seal`]).
const FORMAT: u16 = 2;

/// Id of the key that seals format 2 sections: XChaCha20-Poly1305 under the
/// log seal key derived from the root key. A later key gets a new id.
const SEAL_KEY_ID: u32 = 1;

/// Sealed plaintext is padded to a multiple of this many bytes, so one
/// operation of any kind (the largest, a new account, is about 160 bytes)
/// gives a section of the same size.
const PAD_BUCKET: usize = 256;

/// Create an account with its record and credential in plain form (format
/// 1 logs only; read, never written).
const OP_CREATE_ACCOUNT: u8 = 1;
/// Create an account whose record, credential included, is already sealed.
const OP_CREATE_SEALED_ACCOUNT: u8 = 4;
/// Issue a session without an epoch (format 1 logs only; read as epoch 0).
const OP_ISSUE_SESSION: u8 = 2;
/// Issue a session at the account's epoch.
const OP_ISSUE_SESSION_AT_EPOCH: u8 = 5;
/// Raise an account's epoch: every older session of the account ends.
const OP_RAISE_EPOCH: u8 = 6;
/// Replace an account's sealed record (a standing change).
const OP_UPDATE_ACCOUNT: u8 = 7;

/// Failed sign-ins within [`LOCKOUT_WINDOW_MS`] that lock an account out.
const LOCKOUT_FAILURES: u32 = 10;
/// The window failures are counted in: 15 minutes.
const LOCKOUT_WINDOW_MS: u64 = 15 * 60 * 1000;
/// How long an automatic lock-out lasts: 15 minutes.
const LOCKOUT_MS: u64 = 15 * 60 * 1000;
/// Accounts whose failures are counted at once; older windows are dropped
/// first when it fills.
const MAX_COUNTED: usize = 100_000;
const OP_REVOKE_SESSION: u8 = 3;

/// Revoke reasons in the log.
const REASON_REVOKED: u8 = 1;
const REASON_ROTATED: u8 = 2;

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

/// Standing codes in account records.
const STANDING_ACTIVE: u8 = 1;
const STANDING_PENDING: u8 = 2;
const STANDING_LOCKED_OUT: u8 = 3;
const STANDING_SUSPENDED: u8 = 4;
const STANDING_BANNED: u8 = 5;

/// Credential kind: an Argon2id password hash.
const CREDENTIAL_PASSWORD: u8 = 1;

/// Key labels for the keys derived from the root key.
const TOKEN_KEY_LABEL: &[u8] = b"nex-db 2026 auth token digest";
const IDENTIFIER_KEY_LABEL: &[u8] = b"nex-db 2026 auth identifier digest";
const SEAL_KEY_LABEL: &[u8] = b"nex-db 2026 auth log seal";
const FILE_KEY_LABEL: &[u8] = b"nex-db 2026 auth file";

/// First byte of a sealed account-store value. Plain values from 0.1 and 0.2
/// start with their format byte, 1.
const VALUE_SEALED: u8 = 2;

/// Id of the key that seals account-store values: XChaCha20-Poly1305 under
/// the file key.
const FILE_KEY_ID: u32 = 1;

/// Format of the plaintext inside a sealed account record.
const ACCOUNT_FORMAT_SEALED: u8 = 2;

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
/// Conflict key of an account's epoch: two sign-outs everywhere of one
/// account conflict, so each raises the epoch it read.
fn epoch_key(account: &AccountId) -> Vec<u8> {
    let mut key = Vec::with_capacity(17);
    key.push(b'E');
    key.extend_from_slice(account.as_bytes());
    key
}

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
    /// Seals and opens this engine's log sections.
    seal_key: Zeroizing<[u8; 32]>,
    /// Seals and opens account-store values.
    file_key: Zeroizing<[u8; 32]>,
    accounts: Lsm,
    /// Highest seq whose account changes the account store holds.
    applied: AtomicU64,
    sessions: SessionTable,
    epochs: EpochTable,
    /// Account record versions kept for running snapshots.
    versions: Versions,
    /// Failed sign-ins per account: count and window start.
    failures: Mutex<HashMap<AccountId, (u32, u64)>>,
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
            seal_key: root.derive(SEAL_KEY_LABEL),
            file_key: root.derive(FILE_KEY_LABEL),
            accounts,
            applied: AtomicU64::new(applied),
            sessions: SessionTable::new(),
            epochs: EpochTable::new(),
            versions: Versions::new(),
            failures: Mutex::new(HashMap::new()),
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

    /// The account's record as a snapshot at `at` sees it.
    fn load_account_at(&self, account: AccountId, at: Seq) -> Result<Option<AccountRecord>> {
        let key = account_key(self.collection, account);
        match self.versions.at(&key, at) {
            Some(Some(value)) => self.decode_account(account, &key, &value).map(Some),
            Some(None) => Ok(None),
            None => self.load_account(account),
        }
    }

    /// The account's record, sealed or (from 0.1 and 0.2) plain.
    fn load_account(&self, account: AccountId) -> Result<Option<AccountRecord>> {
        let key = account_key(self.collection, account);
        let Some(value) = self.accounts.get(&key)? else {
            return Ok(None);
        };
        self.decode_account(account, &key, &value).map(Some)
    }

    fn decode_account(
        &self,
        account: AccountId,
        key: &[u8],
        value: &[u8],
    ) -> Result<AccountRecord> {
        if value.first() == Some(&VALUE_SEALED) {
            let plain = open_value(&self.file_key, key, value)?;
            return AccountRecord::decode(&plain);
        }
        // A plain account keeps its credential apart.
        let mut r = Reader::new(value, "an account record", 0);
        if r.u8()? != ACCOUNT_FORMAT {
            return Err(Error::corrupt("an account record", 0));
        }
        let created_ms = r.u64()?;
        let digest = r.fixed::<32>()?;
        let standing = decode_standing(r.u8()?, 0, 0)?;
        let _epoch = r.u32()?;
        r.finish()?;
        let Some(bytes) = self
            .accounts
            .get(credential_key(self.collection, account))?
        else {
            return Err(Error::corrupt("an account without a credential", 0));
        };
        let bytes = Zeroizing::new(bytes);
        let mut r = Reader::new(&bytes, "a credential record", 0);
        if r.u8()? != CREDENTIAL_PASSWORD {
            return Err(Error::corrupt("a credential record", 0));
        }
        let phc = Zeroizing::new(r.str16()?.to_owned());
        r.finish()?;
        Ok(AccountRecord {
            created_ms,
            digest,
            standing,
            phc,
        })
    }

    /// Count a failed sign-in of `account` at `now`. Returns the failures in
    /// the current window.
    fn count_failure(&self, account: AccountId, now: u64) -> u32 {
        let mut failures = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        if failures.len() >= MAX_COUNTED && !failures.contains_key(&account) {
            failures.retain(|_, (_, start)| now.saturating_sub(*start) < LOCKOUT_WINDOW_MS);
            if failures.len() >= MAX_COUNTED {
                return 0;
            }
        }
        let entry = failures.entry(account).or_insert((0, now));
        if now.saturating_sub(entry.1) >= LOCKOUT_WINDOW_MS {
            *entry = (0, now);
        }
        entry.0 += 1;
        entry.0
    }

    fn clear_failures(&self, account: AccountId) {
        let _ = self
            .failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&account);
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
            Some(Slot::Live(session)) if session.epoch != self.epochs.get(session.account) => {
                Validation::Revoked {
                    reason: RevokeReason::SignedOutEverywhere,
                }
            }
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
    fn check(&self, identifier: &str, password: &str) -> Result<Checked> {
        check_password(password)?;
        let found = match normalize_identifier(identifier) {
            Ok(normalized) => match self.account_for(&self.identifier_digest(&normalized))? {
                Some(account) => self.load_account(account)?.map(|record| (account, record)),
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
            Some((account, record)) => match kdf::argon2_check(&record.phc, password.as_bytes()) {
                Ok(()) => Ok(match record.standing.blocked_until(now_ms()) {
                    Some(until) => Checked::Blocked(until),
                    None => Checked::Verified(account),
                }),
                Err(crypt_io::Error::AuthenticationFailed) => Ok(Checked::Wrong(Some(account))),
                Err(_) => Err(Error::corrupt("a stored password hash", 0)),
            },
            None => {
                let _ = kdf::argon2_check(dummy, password.as_bytes());
                Ok(Checked::Wrong(None))
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
    CreateSealedAccount {
        account: AccountId,
        digest: [u8; 32],
        value: &'a [u8],
    },
    IssueSession {
        digest: [u8; 32],
        session: Session,
    },
    RevokeSession {
        digest: [u8; 32],
        reason: RevokeReason,
    },
    RaiseEpoch {
        account: AccountId,
        epoch: u32,
    },
    UpdateAccount {
        account: AccountId,
        value: &'a [u8],
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
            OP_CREATE_SEALED_ACCOUNT => Op::CreateSealedAccount {
                account: AccountId::from_bytes(r.fixed()?),
                digest: r.fixed()?,
                value: r.bytes32()?,
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
                        epoch: 0,
                    },
                }
            }
            OP_ISSUE_SESSION_AT_EPOCH => {
                let digest = r.fixed()?;
                let account = AccountId::from_bytes(r.fixed()?);
                let created_ms = r.u64()?;
                let expires_ms = r.u64()?;
                let epoch = r.u32()?;
                Op::IssueSession {
                    digest,
                    session: Session {
                        account,
                        created_ms,
                        expires_ms,
                        epoch,
                    },
                }
            }
            OP_RAISE_EPOCH => Op::RaiseEpoch {
                account: AccountId::from_bytes(r.fixed()?),
                epoch: r.u32()?,
            },
            OP_UPDATE_ACCOUNT => Op::UpdateAccount {
                account: AccountId::from_bytes(r.fixed()?),
                value: r.bytes32()?,
            },
            OP_REVOKE_SESSION => {
                let digest = r.fixed()?;
                let reason = match r.u8()? {
                    REASON_REVOKED => RevokeReason::Revoked,
                    REASON_ROTATED => RevokeReason::Rotated,
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

    fn apply(&self, seq: Seq, section: &Section<'_>) -> Result<()> {
        if section.collection != self.collection {
            return Err(Error::corrupt("an auth section header", seq));
        }
        let plain;
        let body = match (section.format, section.flags) {
            (FORMAT_PLAIN, 0) => section.body,
            (FORMAT, SEALED) => {
                plain = open(&self.seal_key, seq, section)?;
                unpad(&plain, seq)?
            }
            _ => return Err(Error::corrupt("an auth section header", seq)),
        };
        let ops = decode_ops(seq, body)?;

        // Account changes: one batch with the applied mark, skipped when the
        // store already holds this seq.
        if seq > self.applied.load(Ordering::Acquire) {
            let mut batch = Batch::new();
            for op in &ops {
                if let Op::UpdateAccount { account, value } = op {
                    let key = account_key(self.collection, *account);
                    self.versions
                        .record(&key, seq, Some(value), || Ok(self.accounts.get(&key)?))?;
                    batch.put(key, *value);
                }
                if let Op::CreateSealedAccount {
                    account,
                    digest,
                    value,
                } = op
                {
                    let key = account_key(self.collection, *account);
                    self.versions
                        .record(&key, seq, Some(value), || Ok(self.accounts.get(&key)?))?;
                    batch.put(key, *value);
                    batch.put(identifier_key(self.collection, digest), account.as_bytes());
                }
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
                Op::RaiseEpoch { account, epoch } => self.epochs.raise(account, epoch),
                Op::CreateAccount { .. }
                | Op::CreateSealedAccount { .. }
                | Op::UpdateAccount { .. } => {}
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
        self.versions.prune(watermark);
    }
}

/// An auth operation staged in a transaction.
enum StagedOp {
    CreateAccount {
        account: AccountId,
        digest: [u8; 32],
        /// The account record, sealed while staging (see [`seal_value`]).
        value: Vec<u8>,
    },
    IssueSession {
        digest: [u8; 32],
        account: AccountId,
        created_ms: u64,
        expires_ms: u64,
        epoch: u32,
    },
    RevokeSession {
        digest: [u8; 32],
        reason: RevokeReason,
        at_ms: u64,
    },
    RaiseEpoch {
        account: AccountId,
        epoch: u32,
    },
    UpdateAccount {
        account: AccountId,
        /// The new record, sealed while staging.
        value: Vec<u8>,
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
    /// Epochs this work raised, by account.
    raised: HashMap<AccountId, u32>,
    /// Account records this work replaced, by account.
    updated: HashMap<AccountId, AccountRecord>,
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
            raised: HashMap::new(),
            updated: HashMap::new(),
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
        self.ops.iter().any(|op| {
            matches!(
                op,
                StagedOp::RevokeSession { .. }
                    | StagedOp::RaiseEpoch { .. }
                    | StagedOp::UpdateAccount { .. }
            )
        })
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

    fn sealed(&self) -> bool {
        true
    }

    fn encode(&self, seq: Seq, out: &mut Vec<u8>) -> Result<()> {
        let engine = self.engine;
        let mut plain = Zeroizing::new(Vec::with_capacity(PAD_BUCKET));
        plain.extend_from_slice(&[0; 4]);
        write_ops(&self.ops, &mut plain)?;
        seal(&engine.seal_key, seq, engine.collection, &mut plain, out)
    }
}

/// The operations in plain form: the body of format 1, and the plaintext of
/// format 2.
fn write_ops(ops: &[StagedOp], out: &mut Vec<u8>) -> Result<()> {
    let mut w = Writer::new(out);
    for op in ops {
        match op {
            StagedOp::CreateAccount {
                account,
                digest,
                value,
            } => {
                w.u8(OP_CREATE_SEALED_ACCOUNT);
                w.bytes(account.as_bytes());
                w.bytes(digest);
                w.bytes32(value)?;
            }
            StagedOp::IssueSession {
                digest,
                account,
                created_ms,
                expires_ms,
                epoch,
            } => {
                w.u8(OP_ISSUE_SESSION_AT_EPOCH);
                w.bytes(digest);
                w.bytes(account.as_bytes());
                w.u64(*created_ms);
                w.u64(*expires_ms);
                w.u32(*epoch);
            }
            StagedOp::RevokeSession {
                digest,
                reason,
                at_ms,
            } => {
                w.u8(OP_REVOKE_SESSION);
                w.bytes(digest);
                w.u8(match reason {
                    RevokeReason::Rotated => REASON_ROTATED,
                    _ => REASON_REVOKED,
                });
                w.u64(*at_ms);
            }
            StagedOp::RaiseEpoch { account, epoch } => {
                w.u8(OP_RAISE_EPOCH);
                w.bytes(account.as_bytes());
                w.u32(*epoch);
            }
            StagedOp::UpdateAccount { account, value } => {
                w.u8(OP_UPDATE_ACCOUNT);
                w.bytes(account.as_bytes());
                w.bytes32(value)?;
            }
        }
    }
    Ok(())
}

/// Seal an account-store value under the file key:
/// `2 | key id u32 | nonce [24] | ciphertext | tag [16]`, with the store key
/// as associated data, so a value moved to another key fails to open.
///
/// Values are sealed while staging, never in `apply`: sealing draws a random
/// nonce, and `apply` must reach the same state on every replay. The sealed
/// bytes travel inside the (sealed) log section and `apply` stores them as
/// they are.
fn seal_value(key: &[u8; 32], store_key: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let sealed = Crypt::xchacha20_poly1305()
        .encrypt_with_aad(&key[..], plain, store_key)
        .map_err(|e| Error::storage("sealing an account record", e))?;
    let mut out = Vec::with_capacity(5 + sealed.len());
    out.push(VALUE_SEALED);
    out.extend_from_slice(&FILE_KEY_ID.to_le_bytes());
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Open a value sealed by [`seal_value`].
fn open_value(key: &[u8; 32], store_key: &[u8], value: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let corrupt = || Error::corrupt("a sealed account record", 0);
    let rest = value.strip_prefix(&[VALUE_SEALED]).ok_or_else(corrupt)?;
    let (id, sealed) = rest.split_at_checked(4).ok_or_else(corrupt)?;
    if id != FILE_KEY_ID.to_le_bytes() {
        return Err(corrupt());
    }
    Crypt::xchacha20_poly1305()
        .decrypt_with_aad(&key[..], sealed, store_key)
        .map(Zeroizing::new)
        .map_err(|_| corrupt())
}

/// An account record: what the account store holds per account.
struct AccountRecord {
    created_ms: u64,
    digest: [u8; 32],
    standing: Standing,
    phc: Zeroizing<String>,
}

impl AccountRecord {
    /// The sealed plaintext: format, created time, identifier digest,
    /// standing (code, until, reason), then the credential (kind and
    /// Argon2id string).
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut plain = Zeroizing::new(Vec::with_capacity(60 + self.phc.len()));
        let mut w = Writer::new(&mut plain);
        w.u8(ACCOUNT_FORMAT_SEALED);
        w.u64(self.created_ms);
        w.bytes(&self.digest);
        let (code, until, reason) = encode_standing(self.standing);
        w.u8(code);
        w.u64(until);
        w.u32(reason);
        w.u8(CREDENTIAL_PASSWORD);
        w.str16(&self.phc)?;
        Ok(plain)
    }

    fn decode(plain: &[u8]) -> Result<AccountRecord> {
        let corrupt = || Error::corrupt("a sealed account record", 0);
        let mut r = Reader::new(plain, "a sealed account record", 0);
        if r.u8()? != ACCOUNT_FORMAT_SEALED {
            return Err(corrupt());
        }
        let created_ms = r.u64()?;
        let digest = r.fixed::<32>()?;
        let code = r.u8()?;
        let until = r.u64()?;
        let reason = r.u32()?;
        let standing = decode_standing(code, until, reason)?;
        if r.u8()? != CREDENTIAL_PASSWORD {
            return Err(corrupt());
        }
        let phc = Zeroizing::new(r.str16()?.to_owned());
        r.finish()?;
        Ok(AccountRecord {
            created_ms,
            digest,
            standing,
            phc,
        })
    }

    /// The record sealed for `account` under the engine's file key.
    fn seal(&self, engine: &AuthEngine, account: AccountId) -> Result<Vec<u8>> {
        seal_value(
            &engine.file_key,
            &account_key(engine.collection, account),
            &self.encode()?,
        )
    }
}

/// A standing as stored: code, until (ms, 0 for none), reason.
fn encode_standing(standing: Standing) -> (u8, u64, u32) {
    match standing {
        Standing::PendingVerification => (STANDING_PENDING, 0, 0),
        Standing::LockedOut { until } => (STANDING_LOCKED_OUT, ms_of(until).max(1), 0),
        Standing::Suspended { until, reason } => (
            STANDING_SUSPENDED,
            until.map_or(0, |t| ms_of(t).max(1)),
            reason,
        ),
        Standing::Banned { reason } => (STANDING_BANNED, 0, reason),
        // `Standing` is non-exhaustive only for callers; every variant is
        // listed here.
        Standing::Active => (STANDING_ACTIVE, 0, 0),
    }
}

fn decode_standing(code: u8, until: u64, reason: u32) -> Result<Standing> {
    Ok(match code {
        STANDING_ACTIVE => Standing::Active,
        STANDING_PENDING => Standing::PendingVerification,
        STANDING_LOCKED_OUT => Standing::LockedOut {
            until: time_of(until),
        },
        STANDING_SUSPENDED => Standing::Suspended {
            until: (until != 0).then(|| time_of(until)),
            reason,
        },
        STANDING_BANNED => Standing::Banned { reason },
        _ => return Err(Error::corrupt("an account standing", 0)),
    })
}

/// What checking a password found, before failures are counted.
enum Checked {
    Verified(AccountId),
    /// Wrong password (with the account when the identifier exists), or an
    /// unknown identifier.
    Wrong(Option<AccountId>),
    /// The password matched; the account may not sign in until then.
    Blocked(Option<SystemTime>),
}

/// Associated data of a sealed section: what binds the ciphertext to its
/// place in the log, so a section copied to another commit or engine fails to
/// open.
fn seal_aad(seq: Seq, collection: u32) -> [u8; 16] {
    let mut aad = [0u8; 16];
    aad[..8].copy_from_slice(&seq.to_le_bytes());
    aad[8..10].copy_from_slice(&EngineId::AUTH.0.to_le_bytes());
    aad[10..14].copy_from_slice(&collection.to_le_bytes());
    aad[14..].copy_from_slice(&FORMAT.to_le_bytes());
    aad
}

/// Seal `plain` into `out` as a format 2 body:
/// `key id u32 | nonce [24] | ciphertext | tag [16]`.
///
/// `plain` starts with four bytes reserved for its length; it is padded with
/// zeros to a multiple of [`PAD_BUCKET`] before encryption, so the section's
/// size says how many buckets it holds, not which operations. XChaCha20 takes
/// a random 192-bit nonce, which cannot repeat in practice under one key.
fn seal(
    key: &[u8; 32],
    seq: Seq,
    collection: u32,
    plain: &mut Zeroizing<Vec<u8>>,
    out: &mut Vec<u8>,
) -> Result<()> {
    let len = u32::try_from(plain.len() - 4).map_err(|_| Error::invalid("commit", "too large"))?;
    plain[..4].copy_from_slice(&len.to_le_bytes());
    let padded = plain.len().div_ceil(PAD_BUCKET) * PAD_BUCKET;
    plain.resize(padded, 0);
    let sealed = Crypt::xchacha20_poly1305()
        .encrypt_with_aad(&key[..], plain, &seal_aad(seq, collection))
        .map_err(|e| Error::storage("sealing an auth section", e))?;
    out.extend_from_slice(&SEAL_KEY_ID.to_le_bytes());
    out.extend_from_slice(&sealed);
    Ok(())
}

/// Open a format 2 body. Any change to the body, or to its sequence number,
/// engine, collection, or format, fails as damage.
fn open(key: &[u8; 32], seq: Seq, section: &Section<'_>) -> Result<Zeroizing<Vec<u8>>> {
    let corrupt = || Error::corrupt("a sealed auth section", seq);
    let (id, sealed) = section.body.split_at_checked(4).ok_or_else(corrupt)?;
    if id != SEAL_KEY_ID.to_le_bytes() {
        return Err(corrupt());
    }
    Crypt::xchacha20_poly1305()
        .decrypt_with_aad(&key[..], sealed, &seal_aad(seq, section.collection))
        .map(Zeroizing::new)
        .map_err(|_| corrupt())
}

/// The operations inside opened plaintext, without the padding.
fn unpad(plain: &[u8], seq: Seq) -> Result<&[u8]> {
    let mut r = Reader::new(plain, "a sealed auth section", seq);
    let len =
        usize::try_from(r.u32()?).map_err(|_| Error::corrupt("a sealed auth section", seq))?;
    let ops = r.take(len)?;
    if r.take(plain.len() - 4 - len)?.iter().any(|&b| b != 0) {
        return Err(Error::corrupt("a sealed auth section", seq));
    }
    Ok(ops)
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
        let value = AccountRecord {
            created_ms: now_ms(),
            digest,
            standing: Standing::Active,
            phc: Zeroizing::new(password.0.clone()),
        }
        .seal(engine, account)?;
        self.staged.ops.push(StagedOp::CreateAccount {
            account,
            digest,
            value,
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
        let created_ms = now_ms();
        self.stage_session(
            account,
            created_ms,
            created_ms.saturating_add(spec.ttl_ms()),
        )
    }

    /// Stage a session for `account` at its current epoch (counting a raise
    /// staged in this transaction).
    fn stage_session(
        &mut self,
        account: AccountId,
        created_ms: u64,
        expires_ms: u64,
    ) -> Result<Token> {
        let engine = self.staged.engine;
        let (token, random) = Token::generate()?;
        let digest = engine.token_digest(&random);
        let epoch = self.epoch(account);
        let _ = self.staged.issued.insert(digest);
        self.staged.writes.push(session_key(&digest));
        self.staged.ops.push(StagedOp::IssueSession {
            digest,
            account,
            created_ms,
            expires_ms,
            epoch,
        });
        Ok(token)
    }

    /// The account's epoch as this transaction sees it.
    fn epoch(&self, account: AccountId) -> u32 {
        self.staged
            .raised
            .get(&account)
            .copied()
            .unwrap_or_else(|| self.staged.engine.epochs.get(account))
    }

    /// Sign `account` out everywhere: every session issued before this
    /// commit ends, at once and on every reader, as
    /// `Revoked { reason: SignedOutEverywhere }`. Returns how many sessions
    /// were live. A session issued later in the same transaction stays valid.
    ///
    /// Commits ahead of ordinary commits.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the account does not exist.
    pub fn revoke_all(&mut self, account: AccountId) -> Result<u32> {
        let engine = self.staged.engine;
        if !self.staged.accounts.contains(&account) && !engine.account_exists(account)? {
            return Err(Error::invalid("account", "no such account"));
        }
        let epoch = self.epoch(account);
        let live = engine.sessions.live_for(account, epoch, now_ms());
        let next = epoch
            .checked_add(1)
            .ok_or(Error::invalid("account", "signed out too many times"))?;
        // Sessions staged earlier in this transaction end too.
        self.staged
            .ops
            .retain(|op| !matches!(op, StagedOp::IssueSession { account: a, .. } if *a == account));
        let _ = self.staged.raised.insert(account, next);
        self.staged.writes.push(epoch_key(&account));
        self.staged.ops.push(StagedOp::RaiseEpoch {
            account,
            epoch: next,
        });
        Ok(live)
    }

    /// Replace the session `token` names with a new one for the same
    /// account and the same expiry; the old token becomes
    /// `Revoked { reason: Rotated }`. Use it after a sign-in step-up or a
    /// privilege change, so a token seen before cannot be replayed.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the token names no valid session.
    pub fn rotate(&mut self, token: impl AsRef<str>) -> Result<Token> {
        let engine = self.staged.engine;
        let session = token::parse(token.as_ref())
            .map(|random| engine.token_digest(&random))
            .and_then(|digest| match engine.sessions.get(&digest) {
                Some(Slot::Live(session))
                    if now_ms() < session.expires_ms
                        && session.epoch == self.epoch(session.account) =>
                {
                    Some((digest, session))
                }
                _ => None,
            });
        let Some((digest, session)) = session else {
            return Err(Error::invalid("token", "names no valid session"));
        };
        self.staged.writes.push(session_key(&digest));
        self.staged.ops.push(StagedOp::RevokeSession {
            digest,
            reason: RevokeReason::Rotated,
            at_ms: now_ms(),
        });
        self.stage_session(session.account, now_ms(), session.expires_ms)
    }

    /// Set the account's standing. A standing that takes access away
    /// (`LockedOut`, `Suspended`, `Banned`) also ends every session of the
    /// account, in this commit, ahead of ordinary commits. `by` is the
    /// administrator who set it, or `None` for an automatic change.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the account does not exist, or was created in
    /// this same transaction.
    pub fn set_standing(
        &mut self,
        account: AccountId,
        standing: Standing,
        by: Option<AccountId>,
    ) -> Result<()> {
        // Recorded by the audit chain when it lands; not stored in the record.
        let _ = by;
        let engine = self.staged.engine;
        if self.staged.accounts.contains(&account) {
            return Err(Error::invalid("account", "created in this transaction"));
        }
        let Some(mut record) = self.record(account)? else {
            return Err(Error::invalid("account", "no such account"));
        };
        record.standing = standing;
        let value = record.seal(engine, account)?;
        self.staged.ops.retain(
            |op| !matches!(op, StagedOp::UpdateAccount { account: a, .. } if *a == account),
        );
        let _ = self.staged.updated.insert(account, record);
        self.staged
            .writes
            .push(account_key(engine.collection, account));
        self.staged
            .ops
            .push(StagedOp::UpdateAccount { account, value });
        if standing.blocked_until(now_ms()).is_some() {
            let _ = self.revoke_all(account)?;
        }
        Ok(())
    }

    /// The account's record as this transaction sees it.
    fn record(&self, account: AccountId) -> Result<Option<AccountRecord>> {
        if let Some(record) = self.staged.updated.get(&account) {
            return Ok(Some(AccountRecord {
                created_ms: record.created_ms,
                digest: record.digest,
                standing: record.standing,
                phc: record.phc.clone(),
            }));
        }
        self.staged.engine.load_account(account)
    }

    /// Lock the account out until `until`, unless its standing already keeps
    /// it from signing in.
    fn lock_out(&mut self, account: AccountId, until: SystemTime) -> Result<()> {
        match self.record(account)? {
            Some(record) if record.standing.blocked_until(now_ms()).is_none() => {
                self.set_standing(account, Standing::LockedOut { until }, None)
            }
            _ => Ok(()),
        }
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
            reason: RevokeReason::Revoked,
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

    /// Sign an account out everywhere in its own commit. See
    /// [`AuthTx::revoke_all`].
    ///
    /// ```no_run
    /// # fn main() -> nex_db::Result<()> {
    /// # let db = nex_db::open("data/site")?;
    /// # let account = nex_db::AccountId::from_bytes([1; 16]);
    /// let ended = db.auth().revoke_all(account)?;
    /// # let _ = ended;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// As [`AuthTx::revoke_all`], plus the errors of [`Database::commit`].
    pub fn revoke_all(&self, account: AccountId) -> Result<u32> {
        self.db.commit(|tx| tx.auth().revoke_all(account))
    }

    /// Replace a session's token in its own commit. See
    /// [`AuthTx::rotate`].
    ///
    /// # Errors
    ///
    /// As [`AuthTx::rotate`], plus the errors of [`Database::commit`].
    pub fn rotate(&self, token: impl AsRef<str>) -> Result<Token> {
        let token = token.as_ref();
        self.db.commit(|tx| tx.auth().rotate(token))
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
        match self.verify_password(identifier, password)? {
            Login::Verified(account) => {
                let token = self.issue_session(account, spec)?;
                Ok(SignIn::Success { account, token })
            }
            Login::LockedOut { until } => Ok(SignIn::LockedOut { until }),
            _ => Ok(SignIn::Failed),
        }
    }

    /// Check `password` for `identifier` inside the engine without issuing
    /// a session. Failures are counted per account: ten within fifteen
    /// minutes lock the account out for fifteen minutes, in a durable commit.
    /// An unknown identifier costs the same work as a wrong password, and
    /// both give [`Login::Failed`].
    ///
    /// # Errors
    ///
    /// - [`Error::Invalid`] when the password is empty or longer than 1024
    ///   bytes.
    /// - [`Error::Busy`] when the hashing slots are full.
    /// - The errors of [`Database::commit`] when a lock-out is written.
    pub fn verify_password(&self, identifier: &str, password: &str) -> Result<Login> {
        let engine = self.engine();
        match engine.check(identifier, password)? {
            Checked::Verified(account) => {
                engine.clear_failures(account);
                Ok(Login::Verified(account))
            }
            Checked::Blocked(until) => Ok(Login::LockedOut { until }),
            Checked::Wrong(Some(account)) => {
                let now = now_ms();
                if engine.count_failure(account, now) >= LOCKOUT_FAILURES {
                    let until = time_of(now.saturating_add(LOCKOUT_MS));
                    self.db.commit(|tx| tx.auth().lock_out(account, until))?;
                    engine.clear_failures(account);
                }
                Ok(Login::Failed)
            }
            Checked::Wrong(None) => Ok(Login::Failed),
        }
    }

    /// The account's standing, or `None` when the account does not exist.
    /// A lock-out or suspension that has run out reads as
    /// [`Standing::Active`].
    ///
    /// # Errors
    ///
    /// [`Error::Corrupt`] when the record fails its check, and storage
    /// errors.
    pub fn standing(&self, account: AccountId) -> Result<Option<Standing>> {
        Ok(self
            .engine()
            .load_account(account)?
            .map(|record| record.standing.at(now_ms())))
    }

    /// Set an account's standing in its own commit. See
    /// [`AuthTx::set_standing`].
    ///
    /// # Errors
    ///
    /// As [`AuthTx::set_standing`], plus the errors of [`Database::commit`].
    pub fn set_standing(
        &self,
        account: AccountId,
        standing: Standing,
        by: Option<AccountId>,
    ) -> Result<()> {
        self.db
            .commit(|tx| tx.auth().set_standing(account, standing, by))
    }
}

/// Auth reads at one snapshot, inside [`Database::read`](crate::Database::read).
///
/// Returned by [`Read::auth`](crate::Read::auth). Sessions are read-latest
/// by design: a session revoked after the snapshot is revoked here too.
#[derive(Debug)]
pub struct AuthRead<'r> {
    pub(crate) engine: &'r AuthEngine,
    pub(crate) snapshot: &'r SnapshotGuard<'r>,
}

impl AuthRead<'_> {
    /// As [`Auth::validate`], at the latest state.
    ///
    /// # Errors
    ///
    /// [`Error::SnapshotTooOld`] past the snapshot age limit.
    pub fn validate(&self, token: impl AsRef<str>) -> Result<Validation> {
        if self.snapshot.expired() {
            return Err(Error::SnapshotTooOld);
        }
        Ok(self.engine.validate(token.as_ref()))
    }

    /// The account's standing as of the snapshot, or `None` when the account
    /// did not exist then.
    ///
    /// # Errors
    ///
    /// [`Error::SnapshotTooOld`] past the snapshot age limit, and the errors
    /// of [`Auth::standing`].
    pub fn standing(&self, account: AccountId) -> Result<Option<Standing>> {
        if self.snapshot.expired() {
            return Err(Error::SnapshotTooOld);
        }
        Ok(self
            .engine
            .load_account_at(account, self.snapshot.seq())?
            .map(|record| record.standing.at(now_ms())))
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

    fn sealed_section(body: &[u8], seq: Seq) -> (Seq, Section<'_>) {
        (
            seq,
            Section {
                engine: EngineId::AUTH,
                flags: SEALED,
                format: FORMAT,
                collection: 1,
                body,
            },
        )
    }

    fn sealed_body(key: &[u8; 32], seq: Seq, ops: &[u8]) -> Vec<u8> {
        let mut plain = Zeroizing::new(vec![0; 4]);
        plain.extend_from_slice(ops);
        let mut out = Vec::new();
        seal(key, seq, 1, &mut plain, &mut out).unwrap();
        out
    }

    #[test]
    fn test_seal_open_round_trips_and_pads_to_bucket() {
        let key = [7u8; 32];
        let body = sealed_body(&key, 5, b"some operations");
        // Anything up to one bucket seals to the same size; more takes the
        // next bucket.
        let one = sealed_body(&key, 5, &[1]).len();
        assert_eq!(body.len(), one);
        assert_eq!(sealed_body(&key, 5, &[1; PAD_BUCKET - 4]).len(), one);
        assert_eq!(
            sealed_body(&key, 5, &[1; PAD_BUCKET]).len(),
            one + PAD_BUCKET
        );
        let (seq, section) = sealed_section(&body, 5);
        let plain = open(&key, seq, &section).unwrap();
        assert_eq!(unpad(&plain, seq).unwrap(), b"some operations");
    }

    #[test]
    fn test_open_any_changed_byte_is_corrupt() {
        let key = [7u8; 32];
        let body = sealed_body(&key, 5, b"ops");
        for i in 0..body.len() {
            let mut bad = body.clone();
            bad[i] ^= 1;
            let (seq, section) = sealed_section(&bad, 5);
            assert!(open(&key, seq, &section).is_err(), "byte {i}");
        }
    }

    #[test]
    fn test_open_elsewhere_in_the_log_is_corrupt() {
        let key = [7u8; 32];
        let body = sealed_body(&key, 5, b"ops");
        let (_, section) = sealed_section(&body, 5);
        assert!(open(&key, 6, &section).is_err());
        let moved = Section {
            collection: 2,
            ..section
        };
        assert!(open(&key, 5, &moved).is_err());
        assert!(open(&[8u8; 32], 5, &section).is_err());
    }

    #[test]
    fn test_unpad_nonzero_padding_is_corrupt() {
        let mut plain = vec![0u8; PAD_BUCKET];
        plain[..4].copy_from_slice(&3u32.to_le_bytes());
        assert!(unpad(&plain, 1).is_ok());
        plain[PAD_BUCKET - 1] = 1;
        assert!(unpad(&plain, 1).is_err());
        plain[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(unpad(&plain, 1).is_err());
    }

    fn sealed_len(op: StagedOp) -> usize {
        let mut plain = Zeroizing::new(vec![0; 4]);
        write_ops(&[op], &mut plain).unwrap();
        let mut out = Vec::new();
        seal(&[3u8; 32], 9, 1, &mut plain, &mut out).unwrap();
        out.len()
    }

    #[test]
    fn test_sealed_single_operations_have_one_size() {
        let account = AccountId::from_bytes([1; 16]);
        // A real Argon2id hash string, the longest field of any operation.
        let phc = kdf::argon2_hash(b"a password").unwrap();
        // The largest record: a suspension with an end and a reason.
        let record = AccountRecord {
            created_ms: u64::MAX,
            digest: [2; 32],
            standing: Standing::Suspended {
                until: Some(time_of(u64::MAX / 2)),
                reason: u32::MAX,
            },
            phc: Zeroizing::new(phc),
        };
        let value = seal_value(
            &[5; 32],
            &account_key(1, account),
            &record.encode().unwrap(),
        )
        .unwrap();
        let update = sealed_len(StagedOp::UpdateAccount {
            account,
            value: value.clone(),
        });
        let create = sealed_len(StagedOp::CreateAccount {
            account,
            digest: [2; 32],
            value,
        });
        let issue = sealed_len(StagedOp::IssueSession {
            digest: [2; 32],
            account,
            created_ms: u64::MAX,
            expires_ms: u64::MAX,
            epoch: u32::MAX,
        });
        let revoke = sealed_len(StagedOp::RevokeSession {
            digest: [2; 32],
            reason: RevokeReason::Rotated,
            at_ms: u64::MAX,
        });
        let raise = sealed_len(StagedOp::RaiseEpoch {
            account,
            epoch: u32::MAX,
        });
        assert_eq!(revoke, raise);
        assert_eq!(create, update);
        assert_eq!(create, issue);
        assert_eq!(issue, revoke);
    }

    #[test]
    fn test_apply_reads_plain_format_1_and_refuses_mixed_headers() {
        let dir = std::env::temp_dir().join(format!(
            "nex-db-auth-plain-{}-{}",
            std::process::id(),
            id_forge::ulid::Ulid::new()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(crate::core::keys::KEY_FILE);
        crate::core::keys::create_file_if_missing(&path).unwrap();
        let root = crate::core::keys::load_file(&path).unwrap();
        let engine = AuthEngine::open(&dir.join("accounts"), &root, 1).unwrap();
        // A format 1 body as 0.1 and 0.2 wrote it: issue session, no epoch.
        let mut body = Vec::new();
        let mut w = Writer::new(&mut body);
        w.u8(OP_ISSUE_SESSION);
        w.bytes(&[4; 32]);
        w.bytes(&[1; 16]);
        w.u64(0);
        w.u64(u64::MAX);
        let plain = Section {
            engine: EngineId::AUTH,
            flags: 0,
            format: FORMAT_PLAIN,
            collection: 1,
            body: &body,
        };
        engine.apply(1, &plain).unwrap();
        assert!(matches!(engine.sessions.get(&[4; 32]), Some(Slot::Live(_))));
        // A format 2 section must be sealed, and a format 1 one must not.
        let unsealed = Section {
            format: FORMAT,
            ..plain
        };
        assert!(engine.apply(2, &unsealed).is_err());
        let flagged = Section {
            flags: SEALED,
            ..plain
        };
        assert!(engine.apply(3, &flagged).is_err());
        drop(engine);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_account_record_round_trips_every_standing() {
        let phc = Zeroizing::new("$argon2id$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA".to_owned());
        for standing in [
            Standing::Active,
            Standing::PendingVerification,
            Standing::LockedOut {
                until: time_of(5_000),
            },
            Standing::Suspended {
                until: None,
                reason: 7,
            },
            Standing::Suspended {
                until: Some(time_of(9_000)),
                reason: 8,
            },
            Standing::Banned { reason: 9 },
        ] {
            let record = AccountRecord {
                created_ms: 3,
                digest: [1; 32],
                standing,
                phc: phc.clone(),
            };
            let back = AccountRecord::decode(&record.encode().unwrap()).unwrap();
            assert_eq!(back.standing, standing);
            assert_eq!((back.created_ms, back.digest), (3, [1; 32]));
            assert_eq!(*back.phc, *phc);
        }
    }

    #[test]
    fn test_standing_runs_out_into_active() {
        let locked = Standing::LockedOut {
            until: time_of(100),
        };
        assert_eq!(locked.at(99), locked);
        assert_eq!(locked.at(100), Standing::Active);
        let banned = Standing::Banned { reason: 1 };
        assert_eq!(banned.at(u64::MAX), banned);
        assert_eq!(banned.blocked_until(0), Some(None));
        let open = Standing::Suspended {
            until: None,
            reason: 1,
        };
        assert_eq!(open.blocked_until(u64::MAX), Some(None));
    }

    #[test]
    fn test_sealed_value_round_trips_and_is_bound_to_its_key() {
        let key = [6u8; 32];
        let value = seal_value(&key, b"store key a", b"record").unwrap();
        assert_eq!(value[0], VALUE_SEALED);
        assert_eq!(
            &open_value(&key, b"store key a", &value).unwrap()[..],
            b"record"
        );
        assert!(open_value(&key, b"store key b", &value).is_err());
        assert!(open_value(&[7u8; 32], b"store key a", &value).is_err());
        let mut bad = value.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(open_value(&key, b"store key a", &bad).is_err());
    }
}
