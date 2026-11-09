//! The auth process: hosts the realms' engines and serves the channel.
//!
//! It has no core and no log of its own. It loads the root key from the
//! source the hello names, checks it against `auth/key.check`, and opens
//! each realm's store where an embedded database keeps it, so a database
//! opens in either mode. The main thread reads requests: a session check,
//! which reads memory only, is answered there at once; everything else
//! goes to a pool of workers, so a password hash (tens of milliseconds)
//! never holds up a session check.

use std::{
    collections::{HashMap, VecDeque},
    io::Write,
    path::PathBuf,
    sync::{Arc, Condvar, Mutex, OnceLock, PoisonError},
    time::{Duration, Instant},
};

use crypt_io::Zeroizing;

use super::{
    channel::HELLO_REPLY,
    op,
    wire::{self, ERR, OK, REQUEST_HEAD, get_bool, get_str},
};
use crate::{
    auth::{
        AuthEngine, AuthStaged, LocalTx, Policy,
        keys::ApiKeyId,
        types::{Hashed, HashedPassword, SessionId},
    },
    core::{
        catalog::DEFAULT_REALM,
        codec::{Reader, Writer},
        fs::{self, DirLock},
        keys::{self, Keys, RootKey},
        record::{SEALED, Section},
    },
    engine::{BackupSink, Engine, EngineId, Staged},
    error::{Error, Result},
};

/// Realms besides the default one.
const MAX_REALMS: usize = 15;
/// Password hashes held for the application at once.
const MAX_HASHES: usize = 4096;
/// How long a held hash stays usable.
const HASH_TTL: Duration = Duration::from_secs(10 * 60);
/// Transactions with staged work at once.
const MAX_TXS: usize = 65_536;

/// The engines the auth process hosts.
struct Host {
    dir: PathBuf,
    root: RootKey,
    max_sessions: usize,
    auth: AuthEngine,
    realms: [OnceLock<AuthEngine>; MAX_REALMS],
    hosting: Mutex<()>,
    _lock: DirLock,
}

impl Host {
    /// Open the default realm as the hello asks.
    fn open(hello: &[u8]) -> Result<Host> {
        let mut r = Reader::new(hello, "the hello", 0);
        let dir = PathBuf::from(get_str(&mut r)?);
        let keys = match r.u8()? {
            1 => Keys::in_directory(),
            2 => Keys::file(get_str(&mut r)?),
            3 => Keys::env(get_str(&mut r)?),
            _ => return Err(Error::corrupt("the hello", 0)),
        };
        let new_database = get_bool(&mut r)?;
        let max_sessions = usize::try_from(r.u64()?).unwrap_or(usize::MAX).max(1);
        r.finish()?;
        let auth_dir = dir.join("auth");
        fs::create_dir(&auth_dir)?;
        let lock = crate::auth::lock_auth(&auth_dir)?;
        let root = keys::root_key(&keys, &auth_dir, new_database)?;
        let auth = AuthEngine::open(
            &auth_dir.join("accounts"),
            &root,
            DEFAULT_REALM.id,
            max_sessions,
        )?;
        Ok(Host {
            dir,
            root,
            max_sessions,
            auth,
            realms: [const { OnceLock::new() }; MAX_REALMS],
            hosting: Mutex::new(()),
            _lock: lock,
        })
    }

    fn engine(&self, collection: u32) -> Result<&AuthEngine> {
        if collection == DEFAULT_REALM.id {
            return Ok(&self.auth);
        }
        self.realms
            .iter()
            .filter_map(OnceLock::get)
            .find(|e| e.collection() == collection)
            .ok_or(Error::invalid("realm", "not hosted by the auth process"))
    }

    /// Open realm `collection` when it is new, then take `definition` as
    /// its policy: as the embedded database hosts a realm.
    fn host(&self, collection: u32, definition: &[u8]) -> Result<()> {
        let _hosting = self.hosting.lock().unwrap_or_else(PoisonError::into_inner);
        if let Ok(engine) = self.engine(collection) {
            return engine.adopt(definition);
        }
        let dir = self.dir.join("auth").join("realms");
        fs::create_dir(&dir)?;
        let dir = dir.join(collection.to_string());
        fs::create_dir(&dir)?;
        let mut label = b"nex-db 2026 realm root ".to_vec();
        label.extend_from_slice(&collection.to_be_bytes());
        let engine = AuthEngine::open(
            &dir.join("accounts"),
            &self.root.sub(&label),
            collection,
            self.max_sessions,
        )?;
        engine.adopt(definition)?;
        let slot = self
            .realms
            .iter()
            .find(|s| s.get().is_none())
            .ok_or(Error::invalid(
                "collections",
                "at most 15 realms and 15 spaces besides the defaults",
            ))?;
        slot.set(engine)
            .map_err(|_| Error::invalid("collections", "hosted twice"))
    }
}

/// A password hash held for the application.
struct Held {
    phc: Zeroizing<String>,
    made: Instant,
}

/// What the requests share.
struct State<'h> {
    host: &'h Host,
    txs: Mutex<HashMap<u64, Arc<Mutex<AuthStaged<'h>>>>>,
    hashes: Mutex<HashMap<[u8; 16], Held>>,
    out: Mutex<Box<dyn Write + Send>>,
}

impl<'h> State<'h> {
    /// Write one response. A failed write means the application is gone;
    /// its input ends next, and the process with it.
    fn reply(&self, id: u64, status: u8, body: &[u8]) {
        write_reply(&self.out, id, status, body);
    }

    /// Serve one request. A panic ends the process: the application sees
    /// the channel close and stops writes, rather than talk to a process in
    /// an unknown state.
    fn serve(&self, id: u64, op: u16, payload: &[u8]) {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut body = Vec::with_capacity(64);
            let status = self.handle(op, payload, &mut body);
            (status, body)
        }));
        match outcome {
            Ok((status, body)) => self.reply(id, status, &body),
            Err(_) => std::process::abort(),
        }
    }

    /// Run `op`; its result, or its error, goes into `body`.
    fn handle(&self, op: u16, payload: &[u8], body: &mut Vec<u8>) -> u8 {
        let mut r = Reader::new(payload, "a request to the auth process", 0);
        if op::is_tx(op) {
            return self.tx(op, &mut r, body);
        }
        let mut w = Writer::new(body);
        match self.request(op, &mut r, &mut w).and_then(|()| r.finish()) {
            Ok(()) => OK,
            Err(err) => {
                body.clear();
                wire::put_error(&mut Writer::new(body), &err);
                ERR
            }
        }
    }

    fn request(&self, op: u16, r: &mut Reader<'_>, w: &mut Writer<'_>) -> Result<()> {
        match op {
            op::HASH => return self.hash(r, w),
            op::FORGET_HASH => {
                let id = r.fixed::<16>()?;
                let _ = self.hashes().remove(&id);
                return Ok(());
            }
            op::TX_VALIDATE_READS => {
                let id = r.u64()?;
                let _collection = r.u32()?;
                let snapshot = r.u64()?;
                let clear = match self.txs().get(&id).cloned() {
                    Some(tx) => tx
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .validate_reads(snapshot)
                        .is_ok(),
                    None => true,
                };
                wire::put_bool(w, clear);
                return Ok(());
            }
            op::TX_SEAL => return self.seal(r, w),
            op::TX_RELEASE => {
                let id = r.u64()?;
                let _ = self.txs().remove(&id);
                return Ok(());
            }
            _ => {}
        }
        let collection = r.u32()?;
        if op == op::HOST {
            return self.host.host(collection, r.bytes32()?);
        }
        let engine = self.host.engine(collection)?;
        match op {
            op::APPLY => {
                let seq = r.u64()?;
                let section = Section {
                    engine: EngineId::AUTH,
                    format: r.u16()?,
                    flags: r.u8()?,
                    collection: r.u32()?,
                    body: r.bytes32()?,
                };
                let before = engine.policy();
                let mut changes = Vec::new();
                engine.apply(seq, &section, &mut changes)?;
                wire::put_bool(w, !Arc::ptr_eq(&before, &engine.policy()));
                w.u32(
                    u32::try_from(changes.len())
                        .map_err(|_| Error::invalid("changes", "too many"))?,
                );
                for change in &changes {
                    wire::put_change(w, change)?;
                }
            }
            op::DURABLE => w.u64(engine.durable_through()),
            op::CHECKPOINT => w.u64(engine.checkpoint(r.u64()?)?),
            op::RECLAIM => engine.reclaim(r.u64()?),
            op::BACKUP => {
                let root = PathBuf::from(get_str(r)?);
                let base = PathBuf::from(get_str(r)?);
                let keys_only = get_bool(r)?;
                let mut sink = crate::backup::Sink::new(&root, base, keys_only);
                engine.backup(&mut sink)?;
                if collection == DEFAULT_REALM.id {
                    // The root key file, when it lives in the directory:
                    // copied here, so the application never reads it.
                    sink.file(&root.join("auth").join(keys::KEY_FILE))?;
                }
                let items = sink.into_items();
                w.u32(
                    u32::try_from(items.len())
                        .map_err(|_| Error::invalid("backup", "too many files"))?,
                );
                for (kind, path) in &items {
                    w.u8(*kind);
                    wire::put_str(w, path)?;
                }
            }
            op::VALIDATE => wire::put_validation(w, &engine.validate(get_str(r)?))?,
            op::CHECK => {
                let identifier = get_str(r)?;
                let password = get_str(r)?;
                wire::put_checked(w, &engine.check(identifier, password)?);
            }
            op::CLEAR_FAILURES => engine.clear_failures(wire::get_account(r)?),
            op::COUNT_FAILURE => {
                let account = wire::get_account(r)?;
                w.u32(engine.count_failure(account, r.u64()?));
            }
            op::NEEDS_SECOND_FACTOR => {
                wire::put_bool(w, engine.needs_second_factor(wire::get_account(r)?)?);
            }
            op::ACCOUNT_VIEW => {
                let account = wire::get_account(r)?;
                let at = if get_bool(r)? { Some(r.u64()?) } else { None };
                wire::put_view(w, engine.account_view(account, at)?.as_ref())?;
            }
            op::ACCOUNT_NAMED => {
                wire::put_opt_account(w, engine.account_named(get_str(r)?)?);
            }
            op::SESSIONS => {
                wire::put_session_infos(w, &engine.session_list(wire::get_account(r)?))?;
            }
            op::API_KEY_CHECK => wire::put_key_check(w, &engine.api_key_check(get_str(r)?)?)?,
            #[cfg(feature = "mfa")]
            op::PASSKEYS => {
                wire::mfa::put_passkey_infos(w, &engine.passkey_list(wire::get_account(r)?)?)?;
            }
            op::POLICY => {
                let policy: Arc<Policy> = engine.policy();
                w.bytes32(&policy.encode()?)?;
            }
            _ => return Err(Error::invalid("request", "not one the auth process knows")),
        }
        Ok(())
    }

    fn hashes(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 16], Held>> {
        self.hashes.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn txs(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Arc<Mutex<AuthStaged<'h>>>>> {
        self.txs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hash a password and hold the hash under a new random handle.
    fn hash(&self, r: &mut Reader<'_>, w: &mut Writer<'_>) -> Result<()> {
        let _collection = r.u32()?;
        let password = get_str(r)?;
        let hashed = self.host.auth.hash_password(password)?;
        let phc = Zeroizing::new(hashed.phc()?.to_owned());
        let random =
            crypt_io::generate_key().map_err(|e| Error::storage("drawing random bytes", e))?;
        let mut id = [0u8; 16];
        id.copy_from_slice(&random[..16]);
        let mut hashes = self.hashes();
        if hashes.len() >= MAX_HASHES {
            hashes.retain(|_, held| held.made.elapsed() < HASH_TTL);
            if hashes.len() >= MAX_HASHES {
                return Err(Error::Busy {
                    what: "password hashing",
                });
            }
        }
        let _ = hashes.insert(
            id,
            Held {
                phc,
                made: Instant::now(),
            },
        );
        w.bytes(&id);
        Ok(())
    }

    /// The hashed password an argument names: a held hash, or one sent
    /// whole.
    fn password(&self, r: &mut Reader<'_>) -> Result<HashedPassword> {
        let phc = match r.u8()? {
            1 => get_str(r)?.to_owned(),
            2 => {
                let id = r.fixed::<16>()?;
                let mut hashes = self.hashes();
                match hashes.get(&id) {
                    Some(held) if held.made.elapsed() < HASH_TTL => held.phc.as_str().to_owned(),
                    Some(_) => {
                        let _ = hashes.remove(&id);
                        return Err(expired());
                    }
                    None => return Err(expired()),
                }
            }
            _ => return Err(Error::corrupt("a request to the auth process", 0)),
        };
        Ok(HashedPassword(Hashed::Phc(phc)))
    }

    /// Check a transaction's staged work against commits after its
    /// snapshot, seal its section for `seq`, and record its writes at
    /// `seq`.
    fn seal(&self, r: &mut Reader<'_>, w: &mut Writer<'_>) -> Result<()> {
        let id = r.u64()?;
        let _collection = r.u32()?;
        let snapshot = r.u64()?;
        let reads = get_bool(r)?;
        let seq = r.u64()?;
        let tx = self
            .txs()
            .get(&id)
            .cloned()
            .ok_or(Error::invalid("transaction", "unknown to the auth process"))?;
        let staged = tx.lock().unwrap_or_else(PoisonError::into_inner);
        if staged.validate(snapshot).is_err() || (reads && staged.validate_reads(snapshot).is_err())
        {
            return Err(Error::Conflict);
        }
        let mut sealed = Vec::with_capacity(1024);
        staged.encode(seq, &mut sealed)?;
        staged.reserve(seq);
        w.bytes32(&sealed)
    }

    /// A transaction operation. The reply leads with the staged work's
    /// flags, error or not: bit 0 nothing staged, bit 1 priority class.
    fn tx(&self, op: u16, r: &mut Reader<'_>, body: &mut Vec<u8>) -> u8 {
        let mut flags = 1u8;
        let mut result = Vec::with_capacity(64);
        let outcome = (|| -> Result<()> {
            let id = r.u64()?;
            let collection = r.u32()?;
            let serializable = get_bool(r)?;
            let engine = self.host.engine(collection)?;
            let tx = {
                let mut txs = self.txs();
                match txs.get(&id) {
                    Some(tx) => Arc::clone(tx),
                    None => {
                        if txs.len() >= MAX_TXS {
                            return Err(Error::Busy {
                                what: "the auth process's transactions",
                            });
                        }
                        let tx = Arc::new(Mutex::new(
                            AuthStaged::new(engine).serializable(serializable),
                        ));
                        let _ = txs.insert(id, Arc::clone(&tx));
                        tx
                    }
                }
            };
            let mut staged = tx.lock().unwrap_or_else(PoisonError::into_inner);
            let done = self.tx_op(
                op,
                r,
                &mut LocalTx {
                    staged: &mut staged,
                },
                &mut result,
            );
            flags = u8::from(staged.is_empty()) | (u8::from(staged.priority()) << 1);
            done?;
            r.finish()
        })();
        body.push(flags);
        match outcome {
            Ok(()) => {
                body.extend_from_slice(&result);
                OK
            }
            Err(err) => {
                wire::put_error(&mut Writer::new(body), &err);
                ERR
            }
        }
    }

    fn tx_op(
        &self,
        op: u16,
        r: &mut Reader<'_>,
        tx: &mut LocalTx<'_, '_>,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        let mut w = Writer::new(out);
        let w = &mut w;
        match op {
            op::CREATE_ACCOUNT => {
                let identifier = get_str(r)?;
                let password = self.password(r)?;
                wire::put_account(w, tx.create_account(identifier, &password)?);
            }
            op::ISSUE_SESSION => {
                let account = wire::get_account(r)?;
                let spec = wire::get_spec(r)?;
                wire::put_token(w, &tx.issue_session(account, spec)?)?;
            }
            op::SINGLE_USE_TOKEN | op::STAGE_SINGLE_USE => {
                let purpose = wire::get_purpose(r)?;
                let account = wire::get_account(r)?;
                let ttl = wire::get_duration(r)?;
                let token = if op == op::SINGLE_USE_TOKEN {
                    tx.single_use_token(purpose, account, ttl)?
                } else {
                    tx.stage_single_use(purpose, account, ttl)?
                };
                wire::put_token(w, &token)?;
            }
            op::STAGE_CHALLENGE => {
                wire::put_token(w, &tx.stage_challenge(wire::get_account(r)?)?)?;
            }
            op::REDEEM => {
                let token = get_str(r)?;
                let purpose = wire::get_purpose(r)?;
                wire::put_opt_account(w, tx.redeem(token, purpose)?);
            }
            op::REVOKE_ALL => w.u32(tx.revoke_all(wire::get_account(r)?)?),
            op::ROTATE => wire::put_token(w, &tx.rotate(get_str(r)?)?)?,
            op::SET_STANDING => {
                let account = wire::get_account(r)?;
                let standing = wire::get_standing(r)?;
                let by = wire::get_opt_account(r)?;
                tx.set_standing(account, standing, by)?;
            }
            op::ERASE_ACCOUNT => tx.erase_account(wire::get_account(r)?)?,
            op::REAPPLY => {
                let seq = r.u64()?;
                let format = r.u16()?;
                let flags = r.u8()?;
                if flags & !SEALED != 0 {
                    return Err(Error::corrupt("a log section (flags)", seq));
                }
                let section = Section {
                    engine: EngineId::AUTH,
                    format,
                    flags,
                    collection: r.u32()?,
                    body: r.bytes32()?,
                };
                tx.reapply(seq, &section)?;
            }
            op::SET_PASSWORD => {
                let account = wire::get_account(r)?;
                let password = self.password(r)?;
                tx.set_password(account, &password)?;
            }
            op::ADD_IDENTIFIER => {
                let account = wire::get_account(r)?;
                tx.add_identifier(account, get_str(r)?)?;
            }
            op::REMOVE_IDENTIFIER => {
                let account = wire::get_account(r)?;
                wire::put_bool(w, tx.remove_identifier(account, get_str(r)?)?);
            }
            op::DEFINE_ROLE => w.u32(tx.define_role(wire::get_role(r)?)?.get()),
            op::ASSIGN_ROLES => {
                let account = wire::get_account(r)?;
                tx.assign_roles(account, &wire::get_roles(r)?)?;
            }
            op::LOCK_OUT => {
                let account = wire::get_account(r)?;
                tx.lock_out(account, wire::get_time(r)?)?;
            }
            op::NEW_RECOVERY_CODES => {
                wire::put_codes(w, &tx.new_recovery_codes(wire::get_account(r)?)?)?;
            }
            op::USE_RECOVERY_CODE => {
                let account = wire::get_account(r)?;
                wire::put_bool(w, tx.use_recovery_code(account, get_str(r)?)?);
            }
            op::CREATE_API_KEY => {
                let account = wire::get_account(r)?;
                let n = r.u32()? as usize;
                let mut scopes = Vec::with_capacity(n.min(64));
                for _ in 0..n {
                    scopes.push(get_str(r)?);
                }
                let expiry = wire::get_opt_time(r)?;
                wire::put_api_key(w, &tx.create_api_key(account, &scopes, expiry)?)?;
            }
            op::REVOKE_API_KEY => {
                wire::put_bool(w, tx.revoke_api_key(ApiKeyId(r.fixed()?))?);
            }
            op::REVOKE_SESSION => {
                let account = wire::get_account(r)?;
                wire::put_bool(w, tx.revoke_session(account, SessionId(r.fixed()?))?);
            }
            op::REVOKE => wire::put_bool(w, tx.revoke(get_str(r)?)?),
            #[cfg(feature = "mfa")]
            _ => return mfa_op(op, r, tx, w),
            #[cfg(not(feature = "mfa"))]
            _ => return Err(Error::invalid("request", "not one the auth process knows")),
        }
        Ok(())
    }
}

#[cfg(feature = "mfa")]
fn mfa_op(op: u16, r: &mut Reader<'_>, tx: &mut LocalTx<'_, '_>, w: &mut Writer<'_>) -> Result<()> {
    use crate::auth::passkey::{PasskeyAssertion, PasskeyId, PasskeyRegistration};
    match op {
        op::ADD_TOTP => wire::mfa::put_enrollment(w, &tx.add_totp(wire::get_account(r)?)?),
        op::CONFIRM_TOTP | op::CHECK_TOTP => {
            let account = wire::get_account(r)?;
            let code = get_str(r)?;
            let ok = if op == op::CONFIRM_TOTP {
                tx.confirm_totp(account, code)?
            } else {
                tx.check_totp(account, code)?
            };
            wire::put_bool(w, ok);
        }
        op::REMOVE_TOTP => wire::put_bool(w, tx.remove_totp(wire::get_account(r)?)?),
        op::PASSKEY_REGISTRATION => {
            wire::mfa::put_challenge(w, &tx.passkey_registration(wire::get_account(r)?)?);
        }
        op::PASSKEY_SIGN_IN => wire::mfa::put_challenge(w, &tx.passkey_sign_in()?),
        op::ADD_PASSKEY => {
            let account = wire::get_account(r)?;
            let rp = wire::mfa::get_rp(r)?;
            let client_data_json = r.bytes32()?;
            let authenticator_data = r.bytes32()?;
            let registration = PasskeyRegistration::new(client_data_json, authenticator_data);
            w.bytes(&tx.add_passkey(account, &rp, &registration)?.0);
        }
        op::REMOVE_PASSKEY => {
            let account = wire::get_account(r)?;
            wire::put_bool(w, tx.remove_passkey(account, PasskeyId(r.fixed()?))?);
        }
        op::COMPLETE_PASSKEY => {
            let rp = wire::mfa::get_rp(r)?;
            let credential_id = r.bytes32()?;
            let client_data_json = r.bytes32()?;
            let authenticator_data = r.bytes32()?;
            let signature = r.bytes32()?;
            let assertion = PasskeyAssertion::new(
                credential_id,
                client_data_json,
                authenticator_data,
                signature,
            );
            let spec = wire::get_spec(r)?;
            wire::mfa::put_outcome(w, &tx.complete_passkey(&rp, &assertion, spec)?)?;
        }
        op::COMPLETE_SECOND_FACTOR => {
            let challenge = get_str(r)?;
            let code = get_str(r)?;
            let spec = wire::get_spec(r)?;
            wire::mfa::put_second(w, &tx.complete_second_factor(challenge, code, spec)?)?;
        }
        _ => return Err(Error::invalid("request", "not one the auth process knows")),
    }
    Ok(())
}

fn expired() -> Error {
    Error::invalid(
        "password",
        "hashed more than ten minutes ago, or by another auth process: hash it again",
    )
}

/// A request for the pool: id, op, payload.
type Job = (u64, u16, Vec<u8>);

/// Work for the pool: requests in arrival order, and whether input ended.
#[derive(Default)]
struct Queue {
    jobs: Mutex<(VecDeque<Job>, bool)>,
    ready: Condvar,
}

impl Queue {
    fn push(&self, job: Job) {
        self.jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .0
            .push_back(job);
        self.ready.notify_one();
    }

    fn close(&self) {
        self.jobs.lock().unwrap_or_else(PoisonError::into_inner).1 = true;
        self.ready.notify_all();
    }

    /// The next job, or `None` once input ended and every job is taken.
    fn next(&self) -> Option<Job> {
        let mut jobs = self.jobs.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if let Some(job) = jobs.0.pop_front() {
                return Some(job);
            }
            if jobs.1 {
                return None;
            }
            jobs = self
                .ready
                .wait(jobs)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// Requests answered on the reading thread: memory only, never blocked.
fn inline(op: u16) -> bool {
    matches!(
        op,
        op::VALIDATE | op::RECLAIM | op::TX_RELEASE | op::FORGET_HASH
    )
}

/// Serve the channel on this process's standard input and output until
/// the input ends.
pub(crate) fn serve() -> Result<()> {
    let io = |e: std::io::Error| Error::storage("reading the auth channel", e);
    let mut input = std::io::stdin().lock();
    let out = Mutex::new(raw_stdout());
    let Some(frame) = wire::read_frame(&mut input, REQUEST_HEAD).map_err(io)? else {
        return Ok(());
    };
    let (id, op, payload) = parse(&frame)?;
    if op != op::HELLO {
        return Err(Error::corrupt("the hello", 0));
    }
    let host = match Host::open(payload) {
        Ok(host) => host,
        Err(err) => {
            let mut body = Vec::new();
            wire::put_error(&mut Writer::new(&mut body), &err);
            write_reply(&out, id, ERR, &body);
            return Ok(());
        }
    };
    let state = State {
        host: &host,
        txs: Mutex::new(HashMap::new()),
        hashes: Mutex::new(HashMap::new()),
        out,
    };
    state.reply(id, OK, HELLO_REPLY);
    let queue = Queue::default();
    let workers = std::thread::available_parallelism().map_or(1, usize::from) + 4;
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let _ = scope.spawn(|| {
                while let Some((id, op, payload)) = queue.next() {
                    state.serve(id, op, &payload);
                }
            });
        }
        // Input that ends, fails, or does not parse ends the process: the
        // application sees its channel close.
        while let Ok(Some(frame)) = wire::read_frame(&mut input, REQUEST_HEAD) {
            let Ok((id, op, payload)) = parse(&frame) else {
                break;
            };
            if inline(op) {
                state.serve(id, op, payload);
            } else {
                queue.push((id, op, payload.to_vec()));
            }
        }
        queue.close();
    });
    Ok(())
}

/// Standard output without the line buffer `Stdout` adds, so each reply
/// is one write to the pipe: a reply with a newline byte in it would
/// otherwise go out in two writes, and the application might wake twice.
/// Falls back to `Stdout` when the handle cannot be copied.
fn raw_stdout() -> Box<dyn Write + Send> {
    #[cfg(windows)]
    let copied = {
        use std::os::windows::io::AsHandle;
        std::io::stdout()
            .as_handle()
            .try_clone_to_owned()
            .map(std::fs::File::from)
    };
    #[cfg(unix)]
    let copied = {
        use std::os::fd::AsFd;
        std::io::stdout()
            .as_fd()
            .try_clone_to_owned()
            .map(std::fs::File::from)
    };
    #[cfg(not(any(windows, unix)))]
    let copied: std::io::Result<std::fs::File> = Err(std::io::ErrorKind::Unsupported.into());
    match copied {
        Ok(file) => Box::new(file),
        Err(_) => Box::new(std::io::stdout()),
    }
}

/// A request frame's id, op, and payload.
fn parse(frame: &[u8]) -> Result<(u64, u16, &[u8])> {
    let mut r = Reader::new(frame, "a request to the auth process", 0);
    let id = r.u64()?;
    let op = r.u16()?;
    Ok((id, op, &frame[REQUEST_HEAD..]))
}

/// Write one response. A failed write means the application is gone; its
/// input ends next, and the process with it.
fn write_reply(out: &Mutex<Box<dyn Write + Send>>, id: u64, status: u8, body: &[u8]) {
    if id == 0 {
        return;
    }
    let Ok(frame) = wire::frame(
        |w| {
            w.u64(id);
            w.u8(status);
        },
        |w| {
            w.bytes(body);
            Ok(())
        },
    ) else {
        return;
    };
    let mut out = out.lock().unwrap_or_else(PoisonError::into_inner);
    let _ = out.write_all(&frame).and_then(|()| out.flush());
}
