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

mod audit;
pub(crate) mod roles;
mod sessions;
pub(crate) mod token;
pub(crate) mod types;

use std::{
    collections::{HashMap, HashSet},
    fmt,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock, PoisonError, RwLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};

use crypt_io::{Crypt, Zeroizing, kdf, mac};
use lsm_db::{Batch, Lsm};

use self::{
    audit::{AuditChain, Tail},
    roles::{Account, Policy, Role, RoleId},
    sessions::{EpochTable, SessionTable, Slot},
    token::Token,
    types::{
        HashedPassword, Login, Payload, Purpose, RevokeReason, Session, SessionSpec, SignIn,
        Standing, Validation, ms_of, time_of,
    },
};
use crate::{
    Database,
    core::{
        codec::{Reader, Writer},
        conflict::ConflictTable,
        fs,
        keys::RootKey,
        now_ms,
        pipeline::SnapshotGuard,
        record::{SEALED, Section, Seq},
        versions::Versions,
    },
    engine::{Conflict, Engine, EngineId, Staged},
    error::{Error, Result},
    feed::Change,
    ids::AccountId,
    observe::SecurityEvent,
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
/// operation of any kind (the largest, a session with a full 256-byte
/// payload, is about 350 bytes) gives a section of the same size.
const PAD_BUCKET: usize = 512;

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
/// Replace an account's sealed record (a standing change; 0.3 logs).
const OP_UPDATE_ACCOUNT: u8 = 7;
/// Replace an account's sealed record, saying what changed.
const OP_UPDATE_ACCOUNT_AS: u8 = 8;
/// Point an identifier at an account, or remove it.
const OP_SET_IDENTIFIER: u8 = 9;
/// Replace the realm's role policy.
const OP_SET_POLICY: u8 = 10;

/// What an account update changed, for the audit chain.
const UPDATE_STANDING: u8 = 1;
const UPDATE_PASSWORD: u8 = 2;
const UPDATE_IDENTIFIERS: u8 = 3;
const UPDATE_ROLES: u8 = 4;
/// More than one of the above, in one commit.
const UPDATE_SEVERAL: u8 = 5;

/// Most identifiers one account has (the first and four more). With
/// [`MAX_ACCOUNT_ROLES`] it keeps the largest account record inside one
/// sealed bucket.
const MAX_IDENTIFIERS: usize = 5;
/// Most roles one account holds.
const MAX_ACCOUNT_ROLES: usize = 16;

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

/// The session table has no room: staging keeps it well below its size, so
/// this halts writes rather than lose an acknowledged session.
fn table_full() -> Error {
    Error::Busy {
        what: "the session table",
    }
}

/// Key of the account store's applied-through mark.
const META_APPLIED: &[u8] = b"\0meta/applied";

/// The session checkpoint file, next to the account store.
const SESSIONS_FILE: &str = "sessions.ckpt";

/// Format of the session checkpoint file.
const SESSIONS_FORMAT: u16 = 1;

/// Slot kinds in the session checkpoint.
const SLOT_LIVE: u8 = 1;
const SLOT_REVOKED: u8 = 2;

/// A revocation by `revoke_all`, kept only in checkpoints (the log raises
/// the epoch instead).
const REASON_SIGNED_OUT_EVERYWHERE: u8 = 3;

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
const SINGLE_USE_KEY_LABEL: &[u8] = b"nex-db 2026 auth single-use token digest";

/// The longest a single-use token lives: 30 days.
const MAX_SINGLE_USE_MS: u64 = 30 * 24 * 60 * 60 * 1000;
const IDENTIFIER_KEY_LABEL: &[u8] = b"nex-db 2026 auth identifier digest";
const SEAL_KEY_LABEL: &[u8] = b"nex-db 2026 auth log seal";
const FILE_KEY_LABEL: &[u8] = b"nex-db 2026 auth file";
const AUDIT_KEY_LABEL: &[u8] = b"nex-db 2026 auth audit";

/// First byte of a sealed account-store value. Plain values from 0.1 and 0.2
/// start with their format byte, 1.
const VALUE_SEALED: u8 = 2;

/// Id of the key that seals account-store values: XChaCha20-Poly1305 under
/// the file key.
const FILE_KEY_ID: u32 = 1;

/// Format of the plaintext inside a sealed account record (0.3).
const ACCOUNT_FORMAT_SEALED: u8 = 2;
/// The same with the account's further identifiers and its roles (0.4).
const ACCOUNT_FORMAT_SEALED_ROLES: u8 = 3;

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

fn policy_key(collection: u32) -> Vec<u8> {
    store_key(collection, b'p', b"")
}

/// Conflict key of the role policy: two role definitions conflict.
const POLICY_CONFLICT_KEY: &[u8] = b"P";

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
    /// The account store's directory.
    dir: PathBuf,
    /// The session checkpoint file.
    sessions_file: PathBuf,
    token_key: Zeroizing<[u8; 32]>,
    /// Digests single-use tokens, apart from sessions: one is never the
    /// other.
    single_use_key: Zeroizing<[u8; 32]>,
    identifier_key: Zeroizing<[u8; 32]>,
    /// Seals and opens this engine's log sections.
    seal_key: Zeroizing<[u8; 32]>,
    /// Seals and opens account-store values.
    file_key: Zeroizing<[u8; 32]>,
    accounts: Lsm,
    /// Highest seq whose account changes the account store holds.
    applied: AtomicU64,
    /// The account store's mark at its last flush.
    accounts_durable: AtomicU64,
    /// Highest seq whose session changes the session checkpoint holds.
    sessions_through: AtomicU64,
    /// Keeps a checkpoint's mark from interleaving with an apply's batch.
    writing: Mutex<()>,
    sessions: SessionTable,
    epochs: EpochTable,
    /// The realm's audit chain.
    audit: AuditChain,
    /// Account record versions kept for running snapshots.
    versions: Versions,
    /// Failed sign-ins per account: count and window start.
    failures: Mutex<HashMap<AccountId, (u32, u64)>>,
    conflicts: ConflictTable,
    /// Password hashes in progress, bounded by `max_hashing`.
    hashing: AtomicUsize,
    max_hashing: usize,
    /// Most sessions and tombstones held at once.
    max_sessions: usize,
    /// The realm's roles, replaced as a whole on each change.
    policy: RwLock<Arc<Policy>>,
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
    pub(crate) fn open(
        dir: &Path,
        root: &RootKey,
        collection: u32,
        max_sessions: usize,
    ) -> Result<Self> {
        let accounts = Lsm::open(dir)?;
        let auth_dir = dir.parent().unwrap_or(dir).to_path_buf();
        let sessions_file = auth_dir.join(SESSIONS_FILE);
        let file_key = root.derive(FILE_KEY_LABEL);
        let checkpoint = read_checkpoint(&sessions_file, &file_key)?;
        let audit = AuditChain::open(
            &auth_dir,
            root.derive(AUDIT_KEY_LABEL),
            checkpoint.as_ref().map(|c| c.tail),
        )?;
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
        let policy = match accounts.get(policy_key(collection))? {
            Some(bytes) => Policy::decode(&bytes, 0)?,
            None => Policy::default(),
        };
        let engine = AuthEngine {
            collection,
            dir: dir.to_path_buf(),
            sessions_file,
            token_key: root.derive(TOKEN_KEY_LABEL),
            single_use_key: root.derive(SINGLE_USE_KEY_LABEL),
            identifier_key: root.derive(IDENTIFIER_KEY_LABEL),
            seal_key: root.derive(SEAL_KEY_LABEL),
            file_key,
            accounts,
            applied: AtomicU64::new(applied),
            accounts_durable: AtomicU64::new(applied),
            sessions_through: AtomicU64::new(0),
            writing: Mutex::new(()),
            sessions: SessionTable::new(max_sessions, now_ms()),
            epochs: EpochTable::new(),
            audit,
            versions: Versions::new(),
            failures: Mutex::new(HashMap::new()),
            conflicts: ConflictTable::new(),
            hashing: AtomicUsize::new(0),
            max_hashing,
            max_sessions,
            policy: RwLock::new(Arc::new(policy)),
            dummy: OnceLock::new(),
        };
        if let Some(checkpoint) = checkpoint {
            for (account, epoch) in checkpoint.epochs {
                engine.epochs.raise(account, epoch);
            }
            for (digest, slot, time) in checkpoint.slots {
                let epoch = match slot {
                    Slot::Live(session) => engine.epochs.get(session.account),
                    Slot::Revoked(_) => 0,
                };
                engine
                    .sessions
                    .restore(digest, slot, time, epoch)
                    .map_err(|_| table_full())?;
            }
            engine
                .sessions_through
                .store(checkpoint.through, Ordering::Release);
        }
        Ok(engine)
    }

    /// Write the session checkpoint through `through`: the audit chain's
    /// tail (after syncing the chain), epochs, sessions not yet expired, and
    /// tombstones, sealed under the file key.
    fn save_sessions(&self, through: Seq) -> Result<()> {
        let epochs = self.epochs.snapshot();
        // Slots whose time has passed go first: they are invalid either way.
        let _ = self.sessions.reclaim(now_ms());
        let slots = self.sessions.snapshot();
        let mut plain =
            Zeroizing::new(Vec::with_capacity(8 + epochs.len() * 20 + slots.len() * 70));
        let tail = self.audit.sync()?;
        let mut w = Writer::new(&mut plain);
        tail.encode(&mut w);
        w.u32(u32::try_from(epochs.len()).map_err(|_| Error::invalid("epochs", "too many"))?);
        for (account, epoch) in &epochs {
            w.bytes(account.as_bytes());
            w.u32(*epoch);
        }
        w.u32(u32::try_from(slots.len()).map_err(|_| Error::invalid("sessions", "too many"))?);
        for (digest, slot, seen) in &slots {
            w.bytes(digest);
            match slot {
                Slot::Live(session) => {
                    w.u8(SLOT_LIVE);
                    w.bytes(session.account.as_bytes());
                    w.u64(session.created_ms);
                    w.u64(session.expires_ms);
                    w.u32(session.epoch);
                    w.u64(session.idle_ms);
                    w.u64(session.recheck_ms);
                    w.bytes16(session.payload.as_bytes())?;
                    w.u64(*seen);
                }
                Slot::Revoked(reason) => {
                    w.u8(SLOT_REVOKED);
                    w.u64(*seen);
                    w.u8(match reason {
                        RevokeReason::Rotated => REASON_ROTATED,
                        RevokeReason::SignedOutEverywhere => REASON_SIGNED_OUT_EVERYWHERE,
                        _ => REASON_REVOKED,
                    });
                }
            }
        }
        let sealed = seal_value(&self.file_key, &sessions_aad(through), &plain)?;
        let mut file = Vec::with_capacity(14 + sealed.len());
        let mut w = Writer::new(&mut file);
        w.u16(SESSIONS_FORMAT);
        w.u64(through);
        w.bytes32(&sealed)?;
        fs::write_atomic(&self.sessions_file, &file)?;
        self.sessions_through.store(through, Ordering::Release);
        Ok(())
    }

    /// The realm's roles as last applied.
    fn policy(&self) -> Arc<Policy> {
        Arc::clone(&self.policy.read().unwrap_or_else(PoisonError::into_inner))
    }

    fn single_use_digest(&self, random: &[u8; 32]) -> [u8; 32] {
        mac::blake3_keyed(&self.single_use_key, random)
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
            identifiers: Vec::new(),
            roles: Vec::new(),
        })
    }

    /// Add the audit record of the `n`-th operation of commit `seq`. Called
    /// before the operation changes the session table, so a revocation can
    /// still name the session's account.
    fn audit_op(&self, seq: Seq, n: u32, op: &Op<'_>) -> Result<()> {
        let account = |a: AccountId| format!("account {a}");
        let (at_ms, action, target) = match op {
            Op::CreateAccount {
                account: a,
                created_ms,
                ..
            } => (*created_ms, "account.created", account(*a)),
            Op::CreateSealedAccount {
                account: a, value, ..
            } => {
                let key = account_key(self.collection, *a);
                let created =
                    AccountRecord::decode(&open_value(&self.file_key, &key, value)?)?.created_ms;
                (created, "account.created", account(*a))
            }
            Op::IssueSession { session, .. } => (
                session.created_ms,
                "session.issued",
                account(session.account),
            ),
            Op::RevokeSession {
                digest,
                reason,
                at_ms,
            } => {
                let action = match reason {
                    RevokeReason::Rotated => "session.rotated",
                    _ => "session.revoked",
                };
                let target = match self.sessions.get(digest) {
                    Some(Slot::Live(session)) => account(session.account),
                    _ => "session".to_owned(),
                };
                (*at_ms, action, target)
            }
            Op::RaiseEpoch {
                account: a, at_ms, ..
            } => (*at_ms, "account.signed_out_everywhere", account(*a)),
            Op::UpdateAccount {
                account: a,
                what,
                at_ms,
                ..
            } => {
                let action = match *what {
                    UPDATE_PASSWORD => "account.password_changed",
                    UPDATE_IDENTIFIERS => "account.identifiers_changed",
                    UPDATE_ROLES => "account.roles_changed",
                    UPDATE_SEVERAL => "account.changed",
                    _ => "account.standing_changed",
                };
                (*at_ms, action, account(*a))
            }
            Op::SetIdentifier {
                account: a, at_ms, ..
            } => match a {
                Some(a) => (*at_ms, "identifier.added", account(*a)),
                None => (*at_ms, "identifier.removed", "identifier".to_owned()),
            },
            Op::SetPolicy { at_ms, .. } => (*at_ms, "policy.changed", "roles".to_owned()),
        };
        self.audit.append(seq, n, at_ms, action, &target)
    }

    /// What the change feed reports for `op`: ids and kinds only. Called
    /// before the operation changes the session table, so a revocation can
    /// still name the session's account.
    fn change_of(&self, op: &Op<'_>) -> Option<Change> {
        Some(match op {
            Op::CreateAccount { account, .. } | Op::CreateSealedAccount { account, .. } => {
                Change::AccountCreated { account: *account }
            }
            Op::RevokeSession { digest, .. } => Change::SessionRevoked {
                account: match self.sessions.get(digest) {
                    Some(Slot::Live(session)) => Some(session.account),
                    _ => None,
                },
            },
            Op::RaiseEpoch { account, .. } => Change::SessionRevoked {
                account: Some(*account),
            },
            Op::UpdateAccount {
                account,
                what: UPDATE_STANDING,
                ..
            } => Change::StandingChanged { account: *account },
            Op::UpdateAccount { account, .. } => Change::AccountChanged { account: *account },
            Op::IssueSession { .. } | Op::SetIdentifier { .. } | Op::SetPolicy { .. } => {
                return None;
            }
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
        let now = now_ms();
        // No epoch lookup: signing an account out everywhere turns its
        // sessions into tombstones when the commit applies.
        match self.sessions.get_seen(&digest) {
            None => Validation::Unknown,
            Some((Slot::Revoked(reason), ..)) => Validation::Revoked { reason },
            Some((Slot::Live(session), ..)) if now >= session.expires_ms => Validation::Expired,
            Some((Slot::Live(session), seen, _))
                if session.idle_ms != 0 && now.saturating_sub(seen) >= session.idle_ms =>
            {
                Validation::Expired
            }
            Some((Slot::Live(session), _, place)) => {
                self.sessions.touch(place, now);
                Validation::Valid(session)
            }
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
// Lives for one commit, a few at a time: the session inside is kept by
// value rather than boxed.
#[allow(clippy::large_enum_variant)]
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
        at_ms: u64,
    },
    RaiseEpoch {
        account: AccountId,
        epoch: u32,
        at_ms: u64,
    },
    UpdateAccount {
        account: AccountId,
        what: u8,
        value: &'a [u8],
        at_ms: u64,
    },
    SetIdentifier {
        digest: [u8; 32],
        /// `None` removes the identifier.
        account: Option<AccountId>,
        at_ms: u64,
    },
    SetPolicy {
        value: &'a [u8],
        at_ms: u64,
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
                        idle_ms: 0,
                        recheck_ms: 0,
                        payload: Payload::EMPTY,
                    },
                }
            }
            OP_ISSUE_SESSION_AT_EPOCH => {
                let digest = r.fixed()?;
                let account = AccountId::from_bytes(r.fixed()?);
                let created_ms = r.u64()?;
                let expires_ms = r.u64()?;
                let epoch = r.u32()?;
                let idle_ms = r.u64()?;
                let recheck_ms = r.u64()?;
                let payload = Payload::new(r.bytes16()?)
                    .map_err(|_| Error::corrupt("a session payload", seq))?;
                Op::IssueSession {
                    digest,
                    session: Session {
                        account,
                        created_ms,
                        expires_ms,
                        epoch,
                        idle_ms,
                        recheck_ms,
                        payload,
                    },
                }
            }
            OP_RAISE_EPOCH => Op::RaiseEpoch {
                account: AccountId::from_bytes(r.fixed()?),
                epoch: r.u32()?,
                at_ms: r.u64()?,
            },
            OP_UPDATE_ACCOUNT => Op::UpdateAccount {
                account: AccountId::from_bytes(r.fixed()?),
                what: UPDATE_STANDING,
                value: r.bytes32()?,
                at_ms: r.u64()?,
            },
            OP_UPDATE_ACCOUNT_AS => Op::UpdateAccount {
                account: AccountId::from_bytes(r.fixed()?),
                what: r.u8()?,
                value: r.bytes32()?,
                at_ms: r.u64()?,
            },
            OP_SET_IDENTIFIER => {
                let digest = r.fixed()?;
                let present = r.u8()?;
                let account = AccountId::from_bytes(r.fixed()?);
                Op::SetIdentifier {
                    digest,
                    account: match present {
                        0 => None,
                        1 => Some(account),
                        _ => return Err(Error::corrupt("an identifier operation", seq)),
                    },
                    at_ms: r.u64()?,
                }
            }
            OP_SET_POLICY => Op::SetPolicy {
                value: r.bytes32()?,
                at_ms: r.u64()?,
            },
            OP_REVOKE_SESSION => {
                let digest = r.fixed()?;
                let reason = match r.u8()? {
                    REASON_REVOKED => RevokeReason::Revoked,
                    REASON_ROTATED => RevokeReason::Rotated,
                    _ => return Err(Error::corrupt("an auth revoke reason", seq)),
                };
                let at_ms = r.u64()?;
                Op::RevokeSession {
                    digest,
                    reason,
                    at_ms,
                }
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

    fn apply(&self, seq: Seq, section: &Section<'_>, changes: &mut Vec<Change>) -> Result<()> {
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
            let mut policy = None;
            for op in &ops {
                if let Op::SetIdentifier {
                    digest, account, ..
                } = op
                {
                    let key = identifier_key(self.collection, digest);
                    match account {
                        Some(account) => batch.put(key, account.as_bytes()),
                        None => batch.delete(key),
                    }
                }
                if let Op::SetPolicy { value, .. } = op {
                    policy = Some(Policy::decode(value, seq)?);
                    batch.put(policy_key(self.collection), *value);
                }
                if let Op::UpdateAccount { account, value, .. } = op {
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
                let _writing = self.writing.lock().unwrap_or_else(PoisonError::into_inner);
                self.accounts.write(batch)?;
                self.applied.store(seq, Ordering::Release);
            }
            if let Some(policy) = policy {
                *self.policy.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(policy);
            }
        }

        // Sessions live in memory: the checkpoint holds them through its
        // mark, and the log the rest.
        if seq <= self.sessions_through.load(Ordering::Acquire) {
            return Ok(());
        }
        // Slots whose time has passed make room first. Visits only due
        // slots of the wheel; usually none.
        let _ = self.sessions.reclaim(now_ms());
        for (n, op) in ops.into_iter().enumerate() {
            let n = u32::try_from(n).map_err(|_| Error::corrupt("an auth section", seq))?;
            self.audit_op(seq, n, &op)?;
            if let Some(change) = self.change_of(&op) {
                changes.push(change);
            }
            match op {
                Op::IssueSession { digest, session } => {
                    let epoch = self.epochs.get(session.account);
                    self.sessions
                        .insert(digest, session, epoch)
                        .map_err(|_| table_full())?;
                }
                Op::RevokeSession {
                    digest,
                    reason,
                    at_ms,
                } => self
                    .sessions
                    .revoke(digest, reason, at_ms)
                    .map_err(|_| table_full())?,
                Op::RaiseEpoch { account, epoch, .. } => {
                    self.epochs.raise(account, epoch);
                    self.sessions.raise(account, epoch);
                }
                Op::CreateAccount { .. }
                | Op::CreateSealedAccount { .. }
                | Op::UpdateAccount { .. }
                | Op::SetIdentifier { .. }
                | Op::SetPolicy { .. } => {}
            }
        }
        Ok(())
    }

    fn durable_through(&self) -> Seq {
        self.accounts_durable
            .load(Ordering::Acquire)
            .min(self.sessions_through.load(Ordering::Acquire))
    }

    fn checkpoint(&self, upto: Seq) -> Result<Seq> {
        let mark = {
            let _writing = self.writing.lock().unwrap_or_else(PoisonError::into_inner);
            let mark = upto.max(self.applied.load(Ordering::Acquire));
            let mut batch = Batch::new();
            batch.put(META_APPLIED, mark.to_le_bytes());
            self.accounts.write(batch)?;
            self.applied.store(mark, Ordering::Release);
            mark
        };
        self.accounts.flush()?;
        fs::sync_names(&self.dir)?;
        let _ = self.accounts_durable.fetch_max(mark, Ordering::AcqRel);
        self.save_sessions(upto)?;
        Ok(self.durable_through())
    }

    fn reclaim(&self, watermark: Seq) {
        self.conflicts.prune(watermark);
        self.versions.prune(watermark);
    }
}

/// An auth operation staged in a transaction.
// Lives for one commit, a few at a time: the session inside is kept by
// value rather than boxed.
#[allow(clippy::large_enum_variant)]
enum StagedOp {
    CreateAccount {
        account: AccountId,
        digest: [u8; 32],
        /// The account record, sealed while staging (see [`seal_value`]).
        value: Vec<u8>,
    },
    IssueSession {
        digest: [u8; 32],
        session: Session,
    },
    RevokeSession {
        digest: [u8; 32],
        reason: RevokeReason,
        at_ms: u64,
    },
    RaiseEpoch {
        account: AccountId,
        epoch: u32,
        at_ms: u64,
    },
    UpdateAccount {
        account: AccountId,
        what: u8,
        /// The new record, sealed while staging.
        value: Vec<u8>,
        at_ms: u64,
    },
    SetIdentifier {
        digest: [u8; 32],
        account: Option<AccountId>,
        at_ms: u64,
    },
    SetPolicy {
        value: Vec<u8>,
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
    /// Epochs this work raised, by account.
    raised: HashMap<AccountId, u32>,
    /// Account records this work replaced, by account.
    updated: HashMap<AccountId, AccountRecord>,
    /// Identifiers this work removed.
    removed: HashSet<[u8; 32]>,
    /// The role policy as this work left it.
    policy: Option<Policy>,
    /// Checked at commit as well as the writes: a serializable commit.
    serializable: bool,
    /// Conflict keys of what this work read, when serializable.
    reads: std::sync::Mutex<Vec<Vec<u8>>>,
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
            removed: HashSet::new(),
            policy: None,
            serializable: false,
            reads: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Make the commit serializable: what this work reads is checked too.
    pub(crate) fn serializable(mut self, on: bool) -> Self {
        self.serializable = on;
        self
    }

    /// [`note`](Self::note) `key`, and pass `value` through.
    fn noted<T>(&self, key: Vec<u8>, value: T) -> T {
        self.note(key);
        value
    }

    /// Note that this work read the item conflict key `key` names.
    fn note(&self, key: Vec<u8>) {
        if self.serializable {
            self.reads
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(key);
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

    fn validate_reads(&self, snapshot: Seq) -> std::result::Result<(), Conflict> {
        let reads = self
            .reads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self
            .engine
            .conflicts
            .conflicts(reads.iter().map(Vec::as_slice), snapshot)
        {
            Err(Conflict)
        } else {
            Ok(())
        }
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
            StagedOp::IssueSession { digest, session } => {
                w.u8(OP_ISSUE_SESSION_AT_EPOCH);
                w.bytes(digest);
                w.bytes(session.account.as_bytes());
                w.u64(session.created_ms);
                w.u64(session.expires_ms);
                w.u32(session.epoch);
                w.u64(session.idle_ms);
                w.u64(session.recheck_ms);
                w.bytes16(session.payload.as_bytes())?;
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
            StagedOp::RaiseEpoch {
                account,
                epoch,
                at_ms,
            } => {
                w.u8(OP_RAISE_EPOCH);
                w.bytes(account.as_bytes());
                w.u32(*epoch);
                w.u64(*at_ms);
            }
            StagedOp::UpdateAccount {
                account,
                what,
                value,
                at_ms,
            } => {
                w.u8(OP_UPDATE_ACCOUNT_AS);
                w.bytes(account.as_bytes());
                w.u8(*what);
                w.bytes32(value)?;
                w.u64(*at_ms);
            }
            StagedOp::SetIdentifier {
                digest,
                account,
                at_ms,
            } => {
                w.u8(OP_SET_IDENTIFIER);
                w.bytes(digest);
                w.u8(u8::from(account.is_some()));
                w.bytes(account.unwrap_or(AccountId::from_bytes([0; 16])).as_bytes());
                w.u64(*at_ms);
            }
            StagedOp::SetPolicy { value, at_ms } => {
                w.u8(OP_SET_POLICY);
                w.bytes32(value)?;
                w.u64(*at_ms);
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
#[derive(Clone)]
struct AccountRecord {
    created_ms: u64,
    /// The identifier the account was created with (or, after it was
    /// removed, the oldest one left).
    digest: [u8; 32],
    standing: Standing,
    phc: Zeroizing<String>,
    /// Further identifiers, oldest first.
    identifiers: Vec<[u8; 32]>,
    roles: Vec<RoleId>,
}

impl AccountRecord {
    /// The sealed plaintext: format, created time, identifier digest,
    /// standing (code, until, reason), the credential (kind and Argon2id
    /// string), then the further identifiers and the role ids.
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut plain = Zeroizing::new(Vec::with_capacity(
            64 + self.phc.len() + 32 * self.identifiers.len() + 4 * self.roles.len(),
        ));
        let mut w = Writer::new(&mut plain);
        w.u8(ACCOUNT_FORMAT_SEALED_ROLES);
        w.u64(self.created_ms);
        w.bytes(&self.digest);
        let (code, until, reason) = encode_standing(self.standing);
        w.u8(code);
        w.u64(until);
        w.u32(reason);
        w.u8(CREDENTIAL_PASSWORD);
        w.str16(&self.phc)?;
        w.u8(self.identifiers.len() as u8);
        for digest in &self.identifiers {
            w.bytes(digest);
        }
        w.u8(self.roles.len() as u8);
        for role in &self.roles {
            w.u32(role.get());
        }
        Ok(plain)
    }

    fn decode(plain: &[u8]) -> Result<AccountRecord> {
        let corrupt = || Error::corrupt("a sealed account record", 0);
        let mut r = Reader::new(plain, "a sealed account record", 0);
        let format = r.u8()?;
        if format != ACCOUNT_FORMAT_SEALED && format != ACCOUNT_FORMAT_SEALED_ROLES {
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
        let mut identifiers = Vec::new();
        let mut roles = Vec::new();
        if format == ACCOUNT_FORMAT_SEALED_ROLES {
            for _ in 0..r.u8()? {
                identifiers.push(r.fixed::<32>()?);
            }
            for _ in 0..r.u8()? {
                roles.push(RoleId::from_u32(r.u32()?));
            }
        }
        r.finish()?;
        Ok(AccountRecord {
            created_ms,
            digest,
            standing,
            phc,
            identifiers,
            roles,
        })
    }

    /// Every identifier of the account, the first one first.
    fn all_identifiers(&self) -> impl Iterator<Item = &[u8; 32]> {
        std::iter::once(&self.digest).chain(&self.identifiers)
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

/// What a session checkpoint holds.
struct Checkpoint {
    through: Seq,
    tail: Tail,
    epochs: Vec<(AccountId, u32)>,
    slots: Vec<([u8; 32], Slot, u64)>,
}

/// Read the session checkpoint at `path`, when there is one. A damaged one
/// keeps the database closed: the log below its mark may be gone.
fn read_checkpoint(path: &Path, file_key: &[u8; 32]) -> Result<Option<Checkpoint>> {
    let corrupt = || Error::corrupt("the session checkpoint", 0);
    let Some(bytes) = fs::read_optional(path)? else {
        return Ok(None);
    };
    let mut r = Reader::new(&bytes, "the session checkpoint", 0);
    if r.u16()? != SESSIONS_FORMAT {
        return Err(corrupt());
    }
    let through = r.u64()?;
    let sealed = r.bytes32()?;
    r.finish()?;
    let plain = open_value(file_key, &sessions_aad(through), sealed)?;
    let mut r = Reader::new(&plain, "the session checkpoint", 0);
    let tail = Tail::decode(&mut r)?;
    let mut epochs = Vec::new();
    for _ in 0..r.u32()? {
        epochs.push((AccountId::from_bytes(r.fixed()?), r.u32()?));
    }
    let mut slots = Vec::new();
    for _ in 0..r.u32()? {
        let digest = r.fixed::<32>()?;
        let seen;
        let slot = match r.u8()? {
            SLOT_LIVE => {
                let session = Session {
                    account: AccountId::from_bytes(r.fixed()?),
                    created_ms: r.u64()?,
                    expires_ms: r.u64()?,
                    epoch: r.u32()?,
                    idle_ms: r.u64()?,
                    recheck_ms: r.u64()?,
                    payload: Payload::new(r.bytes16()?).map_err(|_| corrupt())?,
                };
                seen = r.u64()?;
                Slot::Live(session)
            }
            SLOT_REVOKED => {
                seen = r.u64()?;
                Slot::Revoked(match r.u8()? {
                    REASON_REVOKED => RevokeReason::Revoked,
                    REASON_ROTATED => RevokeReason::Rotated,
                    REASON_SIGNED_OUT_EVERYWHERE => RevokeReason::SignedOutEverywhere,
                    _ => return Err(corrupt()),
                })
            }
            _ => return Err(corrupt()),
        };
        slots.push((digest, slot, seen));
    }
    r.finish()?;
    Ok(Some(Checkpoint {
        through,
        tail,
        epochs,
        slots,
    }))
}

/// Associated data of the session checkpoint: binds it to its mark.
fn sessions_aad(through: Seq) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SESSIONS_FILE.len() + 8);
    aad.extend_from_slice(SESSIONS_FILE.as_bytes());
    aad.extend_from_slice(&through.to_le_bytes());
    aad
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
        if self.staged.identifiers.contains(&digest) || {
            self.staged.note(identifier_key(engine.collection, &digest));
            engine.account_for(&digest)
        }?
        .is_some()
        {
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
            identifiers: Vec::new(),
            roles: Vec::new(),
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
        if !self.staged.accounts.contains(&account)
            && !{
                self.staged.note(account_key(engine.collection, account));
                engine.account_exists(account)
            }?
        {
            return Err(Error::invalid("account", "no such account"));
        }
        if engine.sessions.len() + self.staged.issued.len() >= engine.max_sessions {
            return Err(Error::Busy {
                what: "the session table",
            });
        }
        let created_ms = now_ms();
        self.stage_session(Session {
            account,
            created_ms,
            expires_ms: created_ms.saturating_add(spec.ttl_ms()),
            epoch: 0,
            idle_ms: spec.idle_ms(),
            recheck_ms: spec
                .recheck_ms()
                .map_or(0, |after| created_ms.saturating_add(after).max(1)),
            payload: Payload::new(spec.payload_bytes())?,
        })
    }

    /// Issue a token for `account` that works once, for `purpose`, for
    /// `ttl` (at most 30 days): email verification, a password reset, a
    /// sign-in link, a preview. It is not a session: it never validates.
    ///
    /// # Errors
    ///
    /// - [`Error::Invalid`] when the account does not exist or `ttl` is
    ///   longer than 30 days.
    /// - [`Error::Busy`] when the session table is full.
    pub fn single_use_token(
        &mut self,
        purpose: Purpose,
        account: AccountId,
        ttl: Duration,
    ) -> Result<Token> {
        let engine = self.staged.engine;
        if !self.staged.accounts.contains(&account)
            && !{
                self.staged.note(account_key(engine.collection, account));
                engine.account_exists(account)
            }?
        {
            return Err(Error::invalid("account", "no such account"));
        }
        self.stage_single_use(purpose, account, ttl)
    }

    fn stage_single_use(
        &mut self,
        purpose: Purpose,
        account: AccountId,
        ttl: Duration,
    ) -> Result<Token> {
        let engine = self.staged.engine;
        let ttl_ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
        if ttl_ms == 0 || ttl_ms > MAX_SINGLE_USE_MS {
            return Err(Error::invalid("ttl", "must be at most 30 days"));
        }
        if engine.sessions.len() + self.staged.issued.len() >= engine.max_sessions {
            return Err(Error::Busy {
                what: "the session table",
            });
        }
        let created_ms = now_ms();
        let session = Session {
            account,
            created_ms,
            expires_ms: created_ms.saturating_add(ttl_ms),
            epoch: 0,
            idle_ms: 0,
            recheck_ms: 0,
            payload: Payload::new(&purpose.payload())?,
        };
        self.stage_digest(session, |random| engine.single_use_digest(random))
    }

    /// Redeem a single-use token for `purpose`: its account, once. A token
    /// redeemed before, expired, issued for another purpose, or unknown
    /// gives `None`.
    ///
    /// # Errors
    ///
    /// Only storage errors; a malformed token gives `Ok(None)`.
    pub fn redeem(
        &mut self,
        token: impl AsRef<str>,
        purpose: Purpose,
    ) -> Result<Option<AccountId>> {
        let engine = self.staged.engine;
        let Some(random) = token::parse(token.as_ref()) else {
            return Ok(None);
        };
        let digest = engine.single_use_digest(&random);
        // Two redeems of one token conflict on its key: only one lands.
        self.staged.writes.push(session_key(&digest));
        let account = match self
            .staged
            .noted(session_key(&digest), engine.sessions.get(&digest))
        {
            Some(Slot::Live(session))
                if now_ms() < session.expires_ms
                    && session.payload.as_bytes() == purpose.payload()
                    && {
                        self.staged
                            .note(account_key(engine.collection, session.account));
                        engine.account_exists(session.account)
                    }? =>
            {
                session.account
            }
            _ => return Ok(None),
        };
        self.staged.ops.push(StagedOp::RevokeSession {
            digest,
            reason: RevokeReason::Revoked,
            at_ms: now_ms(),
        });
        Ok(Some(account))
    }

    /// Stage a session for `account` at its current epoch (counting a raise
    /// staged in this transaction).
    fn stage_session(&mut self, session: Session) -> Result<Token> {
        let engine = self.staged.engine;
        self.stage_digest(session, |random| engine.token_digest(random))
    }

    fn stage_digest(
        &mut self,
        mut session: Session,
        digest_of: impl FnOnce(&[u8; 32]) -> [u8; 32],
    ) -> Result<Token> {
        let (token, random) = Token::generate()?;
        let digest = digest_of(&random);
        session.epoch = self.epoch(session.account);
        let _ = self.staged.issued.insert(digest);
        self.staged.writes.push(session_key(&digest));
        self.staged
            .ops
            .push(StagedOp::IssueSession { digest, session });
        Ok(token)
    }

    /// The account's epoch as this transaction sees it.
    fn epoch(&self, account: AccountId) -> u32 {
        self.staged
            .raised
            .get(&account)
            .copied()
            .unwrap_or_else(|| {
                self.staged.note(epoch_key(&account));
                self.staged.engine.epochs.get(account)
            })
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
        if !self.staged.accounts.contains(&account)
            && !{
                self.staged.note(account_key(engine.collection, account));
                engine.account_exists(account)
            }?
        {
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
            .retain(|op| !matches!(op, StagedOp::IssueSession { session, .. } if session.account == account));
        let _ = self.staged.raised.insert(account, next);
        self.staged.writes.push(epoch_key(&account));
        self.staged.ops.push(StagedOp::RaiseEpoch {
            account,
            epoch: next,
            at_ms: now_ms(),
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
            .and_then(|digest| {
                match self
                    .staged
                    .noted(session_key(&digest), engine.sessions.get(&digest))
                {
                    Some(Slot::Live(session))
                        if now_ms() < session.expires_ms
                            && session.epoch == self.epoch(session.account) =>
                    {
                        Some((digest, session))
                    }
                    _ => None,
                }
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
        // The new token keeps the session's expiry, idle limit, recheck
        // time, and payload.
        self.stage_session(Session {
            created_ms: now_ms(),
            ..session
        })
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
        let _ = engine;
        self.update_record(account, UPDATE_STANDING, |record| {
            record.standing = standing;
            Ok(())
        })?;
        if standing.blocked_until(now_ms()).is_some() {
            let _ = self.revoke_all(account)?;
        }
        Ok(())
    }

    /// The account's record as this transaction sees it.
    fn record(&self, account: AccountId) -> Result<Option<AccountRecord>> {
        if let Some(record) = self.staged.updated.get(&account) {
            return Ok(Some(record.clone()));
        }
        {
            self.staged
                .note(account_key(self.staged.engine.collection, account));
            self.staged.engine.load_account(account)
        }
    }

    /// Replace the account's record with `change` applied, in this commit;
    /// `what` says what changed, for the audit chain. One record per account
    /// is written, the last.
    fn update_record(
        &mut self,
        account: AccountId,
        what: u8,
        change: impl FnOnce(&mut AccountRecord) -> Result<()>,
    ) -> Result<()> {
        let engine = self.staged.engine;
        if self.staged.accounts.contains(&account) {
            return Err(Error::invalid("account", "created in this transaction"));
        }
        let Some(mut record) = self.record(account)? else {
            return Err(Error::invalid("account", "no such account"));
        };
        change(&mut record)?;
        let value = record.seal(engine, account)?;
        let mut what = what;
        self.staged.ops.retain(|op| match op {
            StagedOp::UpdateAccount {
                account: a,
                what: earlier,
                ..
            } if *a == account => {
                if *earlier != what {
                    what = UPDATE_SEVERAL;
                }
                false
            }
            _ => true,
        });
        let _ = self.staged.updated.insert(account, record);
        self.staged
            .writes
            .push(account_key(engine.collection, account));
        self.staged.ops.push(StagedOp::UpdateAccount {
            account,
            what,
            value,
            at_ms: now_ms(),
        });
        Ok(())
    }

    /// The role policy as this transaction sees it.
    fn policy(&self) -> Policy {
        match &self.staged.policy {
            Some(policy) => policy.clone(),
            None => {
                self.staged.note(POLICY_CONFLICT_KEY.to_vec());
                (*self.staged.engine.policy()).clone()
            }
        }
    }

    /// Replace the account's password. Every session the account has ends,
    /// in this commit; a session issued later in the same transaction
    /// stays.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the account does not exist, or was created in
    /// this same transaction.
    pub fn set_password(&mut self, account: AccountId, password: &HashedPassword) -> Result<()> {
        self.update_record(account, UPDATE_PASSWORD, |record| {
            record.phc = Zeroizing::new(password.0.clone());
            Ok(())
        })?;
        let _ = self.revoke_all(account)?;
        Ok(())
    }

    /// Let the account also sign in with `identifier` (a second email
    /// address, a username). An account has at most five identifiers.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] (`what = "identifier"`) when an account
    ///   already uses the identifier.
    /// - [`Error::Invalid`] when the identifier is not valid (as for
    ///   [`create_account`](Self::create_account)), the account has five,
    ///   or the account does not exist or was created in this transaction.
    pub fn add_identifier(&mut self, account: AccountId, identifier: &str) -> Result<()> {
        let engine = self.staged.engine;
        let normalized = normalize_identifier(identifier)?;
        let digest = engine.identifier_digest(&normalized);
        let taken = self.staged.identifiers.contains(&digest)
            || (!self.staged.removed.contains(&digest) && {
                self.staged.note(identifier_key(engine.collection, &digest));
                engine.account_for(&digest)
            }?
            .is_some());
        if taken {
            return Err(Error::AlreadyExists { what: "identifier" });
        }
        self.update_record(account, UPDATE_IDENTIFIERS, |record| {
            if record.identifiers.len() + 1 >= MAX_IDENTIFIERS {
                return Err(Error::invalid("account", "has five identifiers already"));
            }
            record.identifiers.push(digest);
            Ok(())
        })?;
        let _ = self.staged.identifiers.insert(digest);
        let _ = self.staged.removed.remove(&digest);
        self.staged
            .writes
            .push(identifier_key(engine.collection, &digest));
        self.staged.ops.push(StagedOp::SetIdentifier {
            digest,
            account: Some(account),
            at_ms: now_ms(),
        });
        Ok(())
    }

    /// Stop the account signing in with `identifier`. Returns `false` when
    /// the identifier is not one of the account's.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when it is the account's only identifier (an
    /// account keeps at least one), or the account does not exist or was
    /// created in this transaction.
    pub fn remove_identifier(&mut self, account: AccountId, identifier: &str) -> Result<bool> {
        let engine = self.staged.engine;
        let Ok(normalized) = normalize_identifier(identifier) else {
            return Ok(false);
        };
        let digest = engine.identifier_digest(&normalized);
        let Some(record) = self.record(account)? else {
            return Err(Error::invalid("account", "no such account"));
        };
        if !record.all_identifiers().any(|d| *d == digest) {
            return Ok(false);
        }
        if record.identifiers.is_empty() {
            return Err(Error::invalid("account", "keeps at least one identifier"));
        }
        self.update_record(account, UPDATE_IDENTIFIERS, |record| {
            if record.digest == digest {
                record.digest = record.identifiers.remove(0);
            } else {
                record.identifiers.retain(|d| *d != digest);
            }
            Ok(())
        })?;
        let _ = self.staged.identifiers.remove(&digest);
        let _ = self.staged.removed.insert(digest);
        self.staged
            .writes
            .push(identifier_key(engine.collection, &digest));
        self.staged.ops.push(StagedOp::SetIdentifier {
            digest,
            account: None,
            at_ms: now_ms(),
        });
        Ok(true)
    }

    /// Define a role in the realm and return its id. Roles are never
    /// removed, so an id stays valid.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] (`what = "role"`) when a role has the name.
    /// - [`Error::Invalid`] when a name is empty or longer than 64 bytes,
    ///   the role grants more than 64 permissions or inherits more than 64
    ///   roles, inherits one that is not defined, or the realm has 256.
    pub fn define_role(&mut self, role: Role) -> Result<RoleId> {
        let (next, id) = self.policy().with(role)?;
        let value = next.encode()?;
        self.staged
            .ops
            .retain(|op| !matches!(op, StagedOp::SetPolicy { .. }));
        self.staged.ops.push(StagedOp::SetPolicy {
            value,
            at_ms: now_ms(),
        });
        self.staged.writes.push(POLICY_CONFLICT_KEY.to_vec());
        self.staged.policy = Some(next);
        Ok(id)
    }

    /// Replace the account's roles with `roles` (at most 16; repeats count
    /// once).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when a role is not defined, there are more than
    /// 16, or the account does not exist or was created in this
    /// transaction.
    pub fn assign_roles(&mut self, account: AccountId, roles: &[RoleId]) -> Result<()> {
        let policy = self.policy();
        let mut list: Vec<RoleId> = Vec::with_capacity(roles.len());
        for role in roles {
            if policy.get(*role).is_none() {
                return Err(Error::invalid("role", "not defined"));
            }
            if !list.contains(role) {
                list.push(*role);
            }
        }
        if list.len() > MAX_ACCOUNT_ROLES {
            return Err(Error::invalid("roles", "an account holds at most 16"));
        }
        self.update_record(account, UPDATE_ROLES, |record| {
            record.roles = list;
            Ok(())
        })
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
        let live = matches!(
            {
                self.staged.note(session_key(&digest));
                engine.sessions.get(&digest)
            },
            Some(Slot::Live(_))
        ) || self.staged.issued.contains(&digest);
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
        let validation = self.engine().validate(token.as_ref());
        if matches!(validation, Validation::Revoked { .. }) {
            self.db
                .observers()
                .security(SecurityEvent::RevokedSessionPresented);
        }
        Ok(validation)
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
            Checked::Blocked(until) => {
                self.db.observers().security(SecurityEvent::SignInBlocked);
                Ok(Login::LockedOut { until })
            }
            Checked::Wrong(Some(account)) => {
                let observers = self.db.observers();
                observers.security(SecurityEvent::SignInFailed {
                    account: Some(account),
                });
                let now = now_ms();
                if engine.count_failure(account, now) >= LOCKOUT_FAILURES {
                    let until = time_of(now.saturating_add(LOCKOUT_MS));
                    self.db.commit(|tx| tx.auth().lock_out(account, until))?;
                    engine.clear_failures(account);
                    observers.security(SecurityEvent::LockedOut { account });
                }
                Ok(Login::Failed)
            }
            Checked::Wrong(None) => {
                self.db
                    .observers()
                    .security(SecurityEvent::SignInFailed { account: None });
                Ok(Login::Failed)
            }
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

    /// Issue a single-use token in its own commit. See
    /// [`AuthTx::single_use_token`].
    ///
    /// ```no_run
    /// # fn main() -> nex_db::Result<()> {
    /// use std::time::Duration;
    /// use nex_db::Purpose;
    /// let db = nex_db::open("data/site")?;
    /// # let account = nex_db::AccountId::from_bytes([1; 16]);
    /// let link = db.auth().single_use_token(Purpose::VerifyEmail, account, Duration::from_secs(86_400))?;
    /// // ... later, from the link:
    /// let verified = db.auth().redeem(link.as_str(), Purpose::VerifyEmail)?;
    /// # let _ = verified;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// As [`AuthTx::single_use_token`], plus the errors of
    /// [`Database::commit`].
    pub fn single_use_token(
        &self,
        purpose: Purpose,
        account: AccountId,
        ttl: Duration,
    ) -> Result<Token> {
        self.db
            .commit(|tx| tx.auth().single_use_token(purpose, account, ttl))
    }

    /// A single-use token for the account `identifier` names, or `None`
    /// when none does: for a password reset by email address. The work is
    /// the same either way (a token is committed for no account when none
    /// matches, and never redeems), so answer the request the same way too.
    ///
    /// # Errors
    ///
    /// As [`single_use_token`](Self::single_use_token).
    pub fn single_use_token_for(
        &self,
        identifier: &str,
        purpose: Purpose,
        ttl: Duration,
    ) -> Result<Option<Token>> {
        let engine = self.engine();
        let account = match normalize_identifier(identifier) {
            Ok(normalized) => engine.account_for(&engine.identifier_digest(&normalized))?,
            Err(_) => None,
        };
        let target = account.unwrap_or(AccountId::from_bytes([0; 16]));
        let token = self
            .db
            .commit(|tx| tx.auth().stage_single_use(purpose, target, ttl))?;
        Ok(account.map(|_| token))
    }

    /// Redeem a single-use token in its own commit. See
    /// [`AuthTx::redeem`].
    ///
    /// # Errors
    ///
    /// As [`AuthTx::redeem`], plus the errors of [`Database::commit`].
    pub fn redeem(&self, token: impl AsRef<str>, purpose: Purpose) -> Result<Option<AccountId>> {
        let token = token.as_ref();
        self.db.commit(|tx| tx.auth().redeem(token, purpose))
    }

    /// The account, or `None` when it does not exist: its standing (as
    /// [`standing`](Self::standing) reads it), when it was created, and its
    /// roles. Never a credential or an identifier.
    ///
    /// # Errors
    ///
    /// [`Error::Corrupt`] when the record fails its check, and storage
    /// errors.
    pub fn account(&self, account: AccountId) -> Result<Option<Account>> {
        Ok(self.engine().load_account(account)?.map(|record| Account {
            id: account,
            created_at: time_of(record.created_ms),
            standing: record.standing.at(now_ms()),
            roles: record.roles,
        }))
    }

    /// The account's roles; none when the account does not exist.
    ///
    /// # Errors
    ///
    /// As [`account`](Self::account).
    pub fn roles(&self, account: AccountId) -> Result<Vec<RoleId>> {
        Ok(self
            .engine()
            .load_account(account)?
            .map(|record| record.roles)
            .unwrap_or_default())
    }

    /// True when one of the account's roles, or a role they inherit, grants
    /// `permission` under the current policy. Checks roles only: a session
    /// check and the account's standing come first.
    ///
    /// # Errors
    ///
    /// As [`account`](Self::account).
    pub fn allowed(&self, account: AccountId, permission: &str) -> Result<bool> {
        let roles = self.roles(account)?;
        Ok(self.engine().policy().allows(&roles, permission))
    }

    /// The role with id `role`, if defined.
    #[must_use]
    pub fn role(&self, role: RoleId) -> Option<Role> {
        self.engine().policy().get(role).cloned()
    }

    /// The id of the role named `name`, if defined.
    #[must_use]
    pub fn role_named(&self, name: &str) -> Option<RoleId> {
        self.engine().policy().named(name)
    }

    /// Define a role in its own commit. See [`AuthTx::define_role`].
    ///
    /// # Errors
    ///
    /// As [`AuthTx::define_role`], plus the errors of [`Database::commit`].
    pub fn define_role(&self, role: Role) -> Result<RoleId> {
        self.db.commit(|tx| tx.auth().define_role(role.clone()))
    }

    /// Replace an account's roles in its own commit. See
    /// [`AuthTx::assign_roles`].
    ///
    /// # Errors
    ///
    /// As [`AuthTx::assign_roles`], plus the errors of [`Database::commit`].
    pub fn assign_roles(&self, account: AccountId, roles: &[RoleId]) -> Result<()> {
        self.db.commit(|tx| tx.auth().assign_roles(account, roles))
    }

    /// Replace an account's password in its own commit. See
    /// [`AuthTx::set_password`].
    ///
    /// # Errors
    ///
    /// As [`AuthTx::set_password`], plus the errors of [`Database::commit`].
    pub fn set_password(&self, account: AccountId, password: &HashedPassword) -> Result<()> {
        self.db
            .commit(|tx| tx.auth().set_password(account, password))
    }

    /// Add an identifier in its own commit. See
    /// [`AuthTx::add_identifier`].
    ///
    /// # Errors
    ///
    /// As [`AuthTx::add_identifier`], plus the errors of
    /// [`Database::commit`].
    pub fn add_identifier(&self, account: AccountId, identifier: &str) -> Result<()> {
        self.db
            .commit(|tx| tx.auth().add_identifier(account, identifier))
    }

    /// Remove an identifier in its own commit. See
    /// [`AuthTx::remove_identifier`].
    ///
    /// # Errors
    ///
    /// As [`AuthTx::remove_identifier`], plus the errors of
    /// [`Database::commit`].
    pub fn remove_identifier(&self, account: AccountId, identifier: &str) -> Result<bool> {
        self.db
            .commit(|tx| tx.auth().remove_identifier(account, identifier))
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
            decode_ops(1, &[0xEE]),
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
            identifiers: vec![[3; 32]; MAX_IDENTIFIERS - 1],
            roles: vec![RoleId::from_u32(u32::MAX); MAX_ACCOUNT_ROLES],
        };
        let value = seal_value(
            &[5; 32],
            &account_key(1, account),
            &record.encode().unwrap(),
        )
        .unwrap();
        let update = sealed_len(StagedOp::UpdateAccount {
            account,
            what: UPDATE_SEVERAL,
            value: value.clone(),
            at_ms: u64::MAX,
        });
        let identifier = sealed_len(StagedOp::SetIdentifier {
            digest: [2; 32],
            account: Some(account),
            at_ms: u64::MAX,
        });
        let create = sealed_len(StagedOp::CreateAccount {
            account,
            digest: [2; 32],
            value,
        });
        // A session with the largest payload is the largest single operation.
        let issue = sealed_len(StagedOp::IssueSession {
            digest: [2; 32],
            session: Session {
                account,
                created_ms: u64::MAX,
                expires_ms: u64::MAX,
                epoch: u32::MAX,
                idle_ms: u64::MAX,
                recheck_ms: u64::MAX,
                payload: Payload::new(&[7; crate::auth::types::MAX_PAYLOAD]).unwrap(),
            },
        });
        let revoke = sealed_len(StagedOp::RevokeSession {
            digest: [2; 32],
            reason: RevokeReason::Rotated,
            at_ms: u64::MAX,
        });
        let raise = sealed_len(StagedOp::RaiseEpoch {
            account,
            epoch: u32::MAX,
            at_ms: u64::MAX,
        });
        assert_eq!(revoke, raise);
        assert_eq!(revoke, identifier);
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
        let engine = AuthEngine::open(&dir.join("accounts"), &root, 1, 1_000_000).unwrap();
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
        engine.apply(1, &plain, &mut Vec::new()).unwrap();
        assert!(matches!(engine.sessions.get(&[4; 32]), Some(Slot::Live(_))));
        // A format 2 section must be sealed, and a format 1 one must not.
        let unsealed = Section {
            format: FORMAT,
            ..plain
        };
        assert!(engine.apply(2, &unsealed, &mut Vec::new()).is_err());
        let flagged = Section {
            flags: SEALED,
            ..plain
        };
        assert!(engine.apply(3, &flagged, &mut Vec::new()).is_err());
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
                identifiers: vec![[4; 32]],
                roles: vec![RoleId::from_u32(2)],
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

    #[test]
    fn test_audit_chain_records_every_security_write_and_verifies() {
        let dir = std::env::temp_dir().join(format!(
            "nex-db-audit-{}-{}",
            std::process::id(),
            id_forge::ulid::Ulid::new()
        ));
        let auth_dir = dir.join("auth");
        let chain = auth_dir.join(audit::AUDIT_FILE);
        let key = || {
            crate::core::keys::load_file(&auth_dir.join(crate::core::keys::KEY_FILE))
                .unwrap()
                .derive(AUDIT_KEY_LABEL)
        };
        {
            let db = crate::open(&dir).unwrap();
            let pw = db.auth().hash_password("pw").unwrap();
            let ann = db.auth().create_account("ann@example.com", &pw).unwrap();
            let bo = db.auth().create_account("bo@example.com", &pw).unwrap();
            let t = db.auth().issue_session(ann, SessionSpec::web()).unwrap();
            let _ = db.auth().issue_session(bo, SessionSpec::web()).unwrap();
            assert!(db.auth().revoke(&t).unwrap());
            let _ = db.auth().revoke_all(bo).unwrap();
            db.auth()
                .set_standing(ann, Standing::Banned { reason: 1 }, None)
                .unwrap();
        }
        // Two accounts, two sessions, a revocation, a sign-out everywhere,
        // and a ban (the record and the sign-out it implies).
        assert_eq!(audit::verify_file(&chain, &key()).unwrap(), 8);

        {
            let db = crate::open(&dir).unwrap();
            let bo = match db.auth().verify_password("bo@example.com", "pw").unwrap() {
                Login::Verified(bo) => bo,
                other => panic!("{other:?}"),
            };
            let _ = db.auth().issue_session(bo, SessionSpec::web()).unwrap();
        }
        assert_eq!(audit::verify_file(&chain, &key()).unwrap(), 9);

        let bytes = std::fs::read(&chain).unwrap();
        for i in [audit_trail::codec::FILE_HEADER_LEN + 9, bytes.len() - 3] {
            let mut bad = bytes.clone();
            bad[i] ^= 1;
            std::fs::write(&chain, &bad).unwrap();
            assert!(audit::verify_file(&chain, &key()).is_err(), "byte {i}");
        }
        std::fs::write(&chain, &bytes).unwrap();
        // Another key does not verify it either.
        assert!(audit::verify_file(&chain, &[9; 32]).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
