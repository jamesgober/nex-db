//! The application's stand-ins for the auth engines in the auth process.

use std::{
    path::Path,
    sync::{
        Arc, Mutex, PoisonError, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use super::{
    Channel, HashHandle,
    channel::Reply,
    op,
    wire::{self, get_bool, get_str, put_bool, put_str},
};
use crate::{
    auth::{
        AccountView, Checked, FORMAT, HashedPassword,
        keys::{ApiKey, ApiKeyCheck, ApiKeyId},
        realm::RealmPolicy,
        recovery::RecoveryCodes,
        roles::{Policy, Role, RoleId},
        token::Token,
        types::{Hashed, Purpose, SessionId, SessionInfo, SessionSpec, Standing, Validation},
    },
    core::{
        codec::{Reader, Writer},
        record::{Section, Seq},
    },
    engine::{BackupSink, Conflict, Engine, EngineId, Staged},
    error::{Error, Result},
    feed::Change,
    ids::AccountId,
};

/// A transaction id the auth process keys staged work by: unique for the
/// life of the channel.
static NEXT_TX: AtomicU64 = AtomicU64::new(1);

/// One realm's engine, in the auth process.
pub(crate) struct RemoteAuth {
    channel: Arc<Channel>,
    collection: u32,
    /// The realm's policy, from its catalog definition (not secret).
    realm: RwLock<RealmPolicy>,
    /// The realm's roles, fetched when first needed and dropped when a
    /// commit changes them.
    policy: Mutex<Option<Arc<Policy>>>,
    /// The last reclaim watermark sent.
    reclaimed: AtomicU64,
}

impl std::fmt::Debug for RemoteAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteAuth")
            .field("collection", &self.collection)
            .finish_non_exhaustive()
    }
}

impl RemoteAuth {
    /// Have the auth process host realm `collection` with `definition`.
    pub(crate) fn host(
        channel: &Arc<Channel>,
        collection: u32,
        definition: &[u8],
    ) -> Result<RemoteAuth> {
        let remote = RemoteAuth {
            channel: Arc::clone(channel),
            collection,
            realm: RwLock::new(RealmPolicy::new()),
            policy: Mutex::new(None),
            reclaimed: AtomicU64::new(0),
        };
        remote.adopt(definition)?;
        Ok(remote)
    }

    /// Take `definition` (the realm's catalog definition) as its policy,
    /// here and in the auth process.
    pub(crate) fn adopt(&self, definition: &[u8]) -> Result<()> {
        let policy =
            RealmPolicy::decode(definition).map_err(|_| Error::corrupt("a realm definition", 0))?;
        self.call(op::HOST, |w| w.bytes32(definition), |_| Ok(()))?;
        *self.realm.write().unwrap_or_else(PoisonError::into_inner) = policy;
        Ok(())
    }

    pub(crate) fn collection(&self) -> u32 {
        self.collection
    }

    /// One round trip: the realm, what `args` writes; the result `read`
    /// decodes.
    fn call<T>(
        &self,
        op: u16,
        args: impl FnOnce(&mut Writer<'_>) -> Result<()>,
        read: impl FnOnce(&mut Reader<'_>) -> Result<T>,
    ) -> Result<T> {
        let collection = self.collection;
        self.channel
            .request(op, |w| {
                w.u32(collection);
                args(w)
            })?
            .decode(read)
    }

    pub(crate) fn validate(&self, token: &str) -> Result<(Validation, bool)> {
        self.call(
            op::VALIDATE,
            |w| put_str(w, token),
            wire::get_checked_validation,
        )
    }

    pub(crate) fn hash_password(&self, password: &str) -> Result<HashedPassword> {
        let id = self.call(op::HASH, |w| put_str(w, password), |r| r.fixed::<16>())?;
        Ok(HashedPassword(Hashed::Remote(HashHandle {
            id,
            channel: Arc::downgrade(&self.channel),
        })))
    }

    pub(crate) fn check(&self, identifier: &str, password: &str) -> Result<Checked> {
        self.call(
            op::CHECK,
            |w| {
                put_str(w, identifier)?;
                put_str(w, password)
            },
            wire::get_checked,
        )
    }

    pub(crate) fn clear_failures(&self, key: [u8; 16]) -> Result<()> {
        self.call(
            op::CLEAR_FAILURES,
            |w| {
                w.bytes(&key);
                Ok(())
            },
            |_| Ok(()),
        )
    }

    /// When the lock-out this failure started ends (0 on the wire for none).
    pub(crate) fn count_failure(&self, key: [u8; 16], now: u64) -> Result<Option<u64>> {
        self.call(
            op::COUNT_FAILURE,
            |w| {
                w.bytes(&key);
                w.u64(now);
                Ok(())
            },
            |r| Ok(Some(r.u64()?).filter(|&until| until != 0)),
        )
    }

    #[cfg(feature = "mfa")]
    pub(crate) fn locked_until(&self, key: [u8; 16], now: u64) -> Result<Option<u64>> {
        self.call(
            op::LOCKED_UNTIL,
            |w| {
                w.bytes(&key);
                w.u64(now);
                Ok(())
            },
            |r| Ok(Some(r.u64()?).filter(|&until| until != 0)),
        )
    }

    pub(crate) fn needs_second_factor(&self, account: AccountId) -> Result<bool> {
        self.call(
            op::NEEDS_SECOND_FACTOR,
            |w| {
                wire::put_account(w, account);
                Ok(())
            },
            get_bool,
        )
    }

    pub(crate) fn account_view(
        &self,
        account: AccountId,
        at: Option<Seq>,
    ) -> Result<Option<AccountView>> {
        self.call(
            op::ACCOUNT_VIEW,
            |w| {
                wire::put_account(w, account);
                match at {
                    Some(seq) => {
                        w.u8(1);
                        w.u64(seq);
                    }
                    None => w.u8(0),
                }
                Ok(())
            },
            wire::get_view,
        )
    }

    pub(crate) fn account_named(&self, identifier: &str) -> Result<Option<AccountId>> {
        self.call(
            op::ACCOUNT_NAMED,
            |w| put_str(w, identifier),
            wire::get_opt_account,
        )
    }

    pub(crate) fn sessions(&self, account: AccountId) -> Result<Vec<SessionInfo>> {
        self.call(
            op::SESSIONS,
            |w| {
                wire::put_account(w, account);
                Ok(())
            },
            wire::get_session_infos,
        )
    }

    pub(crate) fn api_key_check(&self, text: &str) -> Result<ApiKeyCheck> {
        self.call(op::API_KEY_CHECK, |w| put_str(w, text), wire::get_key_check)
    }

    #[cfg(feature = "mfa")]
    pub(crate) fn passkeys(
        &self,
        account: AccountId,
    ) -> Result<Vec<crate::auth::passkey::PasskeyInfo>> {
        self.call(
            op::PASSKEYS,
            |w| {
                wire::put_account(w, account);
                Ok(())
            },
            wire::mfa::get_passkey_infos,
        )
    }

    /// The realm's roles: kept here until a commit changes them.
    pub(crate) fn policy(&self) -> Result<Arc<Policy>> {
        if let Some(policy) = &*self.policy.lock().unwrap_or_else(PoisonError::into_inner) {
            return Ok(Arc::clone(policy));
        }
        let policy =
            Arc::new(self.call(op::POLICY, |_| Ok(()), |r| Policy::decode(r.bytes32()?, 0))?);
        *self.policy.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&policy));
        Ok(policy)
    }
}

impl Engine for RemoteAuth {
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
        RealmPolicy::decode(definition).map(|_| ())
    }

    fn apply(&self, seq: Seq, section: &Section<'_>, changes: &mut Vec<Change>) -> Result<()> {
        let policy_changed = self.call(
            op::APPLY,
            |w| {
                w.u64(seq);
                w.u16(section.format);
                w.u8(section.flags);
                w.u32(section.collection);
                w.bytes32(section.body)
            },
            |r| {
                let policy_changed = get_bool(r)?;
                for _ in 0..r.u32()? {
                    changes.push(wire::get_change(r)?);
                }
                Ok(policy_changed)
            },
        )?;
        if policy_changed {
            *self.policy.lock().unwrap_or_else(PoisonError::into_inner) = None;
        }
        Ok(())
    }

    /// 0 when the auth process cannot be asked: recovery then replays from
    /// the start of the log, and no checkpoint truncates it.
    fn durable_through(&self) -> Seq {
        self.call(op::DURABLE, |_| Ok(()), |r| r.u64()).unwrap_or(0)
    }

    fn checkpoint(&self, upto: Seq) -> Result<Seq> {
        self.call(
            op::CHECKPOINT,
            |w| {
                w.u64(upto);
                Ok(())
            },
            |r| r.u64(),
        )
    }

    fn reclaim(&self, watermark: Seq) {
        // Sent only when it moved: commits call this after every commit.
        if self.reclaimed.swap(watermark, Ordering::AcqRel) == watermark {
            return;
        }
        let collection = self.collection;
        self.channel.send(op::RECLAIM, |w| {
            w.u32(collection);
            w.u64(watermark);
            Ok(())
        });
    }

    /// The auth process writes its files into the backup itself; this
    /// process never reads them.
    fn backup(&self, out: &mut dyn BackupSink) -> Result<()> {
        let (root, base, keys_only) = out.target();
        let (root, base) = (utf8(root)?, utf8(base)?);
        let items = self.call(
            op::BACKUP,
            |w| {
                put_str(w, root)?;
                put_str(w, base)?;
                put_bool(w, keys_only);
                Ok(())
            },
            |r| {
                let n = r.u32()? as usize;
                let mut items = Vec::with_capacity(n.min(64));
                for _ in 0..n {
                    let kind = r.u8()?;
                    items.push((kind, get_str(r)?.to_owned()));
                }
                Ok(items)
            },
        )?;
        out.merge(items)
    }
}

/// `path` as UTF-8, as the channel carries paths.
pub(crate) fn utf8(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or(Error::invalid("path", "must be UTF-8 with split auth"))
}

/// One transaction's work in one realm, staged in the auth process under
/// this part's id until the part is dropped.
pub(crate) struct RemoteStaged<'db> {
    remote: &'db RemoteAuth,
    id: u64,
    serializable: bool,
    /// What the last operation's reply said of the staged work.
    empty: bool,
    priority: bool,
    /// An operation reached the auth process: it holds state to release.
    touched: bool,
    /// Set by `validate`: the check runs with the sealing, in one round trip.
    snapshot: AtomicU64,
    /// Set by `validate_reads` for a part that writes too.
    check_reads: AtomicBool,
}

impl<'db> RemoteStaged<'db> {
    pub(crate) fn new(remote: &'db RemoteAuth, serializable: bool) -> Self {
        RemoteStaged {
            remote,
            id: NEXT_TX.fetch_add(1, Ordering::Relaxed),
            serializable,
            empty: true,
            priority: false,
            touched: false,
            snapshot: AtomicU64::new(0),
            check_reads: AtomicBool::new(false),
        }
    }

    pub(crate) fn collection(&self) -> u32 {
        self.remote.collection
    }

    /// One operation: run in the auth process on this part's staged work.
    fn tx<T>(
        &mut self,
        op: u16,
        args: impl FnOnce(&mut Writer<'_>) -> Result<()>,
        read: impl FnOnce(&mut Reader<'_>) -> Result<T>,
    ) -> Result<T> {
        let (id, collection, serializable) = (self.id, self.remote.collection, self.serializable);
        self.touched = true;
        let reply: Reply = self.remote.channel.request(op, |w| {
            w.u64(id);
            w.u32(collection);
            put_bool(w, serializable);
            args(w)
        })?;
        let mut r = Reader::new(reply.body(), wire::REPLY, 0);
        let flags = r.u8().map_err(wire::malformed)?;
        self.empty = flags & 1 != 0;
        self.priority = flags & 2 != 0;
        if reply.status == wire::OK {
            read(&mut r)
                .and_then(|value| r.finish().map(|()| value))
                .map_err(wire::malformed)
        } else {
            Err(wire::get_error(&mut r))
        }
    }

    fn account_op<T>(
        &mut self,
        op: u16,
        account: AccountId,
        read: impl FnOnce(&mut Reader<'_>) -> Result<T>,
    ) -> Result<T> {
        self.tx(
            op,
            |w| {
                wire::put_account(w, account);
                Ok(())
            },
            read,
        )
    }

    pub(crate) fn create_account(
        &mut self,
        identifier: &str,
        password: &HashedPassword,
    ) -> Result<AccountId> {
        self.tx(
            op::CREATE_ACCOUNT,
            |w| {
                put_str(w, identifier)?;
                put_password(w, password)
            },
            wire::get_account,
        )
    }

    pub(crate) fn plant_decoy(&mut self) -> Result<Token> {
        self.tx(op::PLANT_DECOY, |_| Ok(()), wire::get_token)
    }

    pub(crate) fn issue_session(&mut self, account: AccountId, spec: SessionSpec) -> Result<Token> {
        self.tx(
            op::ISSUE_SESSION,
            |w| {
                wire::put_account(w, account);
                wire::put_spec(w, &spec)
            },
            wire::get_token,
        )
    }

    fn single_use(
        &mut self,
        op: u16,
        purpose: Purpose,
        account: AccountId,
        ttl: Duration,
    ) -> Result<Token> {
        self.tx(
            op,
            |w| {
                wire::put_purpose(w, purpose);
                wire::put_account(w, account);
                wire::put_duration(w, ttl);
                Ok(())
            },
            wire::get_token,
        )
    }

    pub(crate) fn single_use_token(
        &mut self,
        purpose: Purpose,
        account: AccountId,
        ttl: Duration,
    ) -> Result<Token> {
        self.single_use(op::SINGLE_USE_TOKEN, purpose, account, ttl)
    }

    pub(crate) fn stage_single_use(
        &mut self,
        purpose: Purpose,
        account: AccountId,
        ttl: Duration,
    ) -> Result<Token> {
        self.single_use(op::STAGE_SINGLE_USE, purpose, account, ttl)
    }

    pub(crate) fn stage_challenge(&mut self, account: AccountId) -> Result<Token> {
        self.account_op(op::STAGE_CHALLENGE, account, wire::get_token)
    }

    pub(crate) fn redeem(&mut self, token: &str, purpose: Purpose) -> Result<Option<AccountId>> {
        self.tx(
            op::REDEEM,
            |w| {
                put_str(w, token)?;
                wire::put_purpose(w, purpose);
                Ok(())
            },
            wire::get_opt_account,
        )
    }

    pub(crate) fn revoke_all(&mut self, account: AccountId) -> Result<u32> {
        self.account_op(op::REVOKE_ALL, account, |r| r.u32())
    }

    pub(crate) fn rotate(&mut self, token: &str) -> Result<Token> {
        self.tx(op::ROTATE, |w| put_str(w, token), wire::get_token)
    }

    pub(crate) fn set_standing(
        &mut self,
        account: AccountId,
        standing: Standing,
        by: Option<AccountId>,
    ) -> Result<()> {
        self.tx(
            op::SET_STANDING,
            |w| {
                wire::put_account(w, account);
                wire::put_standing(w, standing);
                wire::put_opt_account(w, by);
                Ok(())
            },
            |_| Ok(()),
        )
    }

    pub(crate) fn erase_account(&mut self, account: AccountId) -> Result<()> {
        self.account_op(op::ERASE_ACCOUNT, account, |_| Ok(()))
    }

    pub(crate) fn reapply(&mut self, seq: Seq, section: &Section<'_>) -> Result<()> {
        self.tx(
            op::REAPPLY,
            |w| {
                w.u64(seq);
                w.u16(section.format);
                w.u8(section.flags);
                w.u32(section.collection);
                w.bytes32(section.body)
            },
            |_| Ok(()),
        )
    }

    pub(crate) fn set_password(
        &mut self,
        account: AccountId,
        password: &HashedPassword,
    ) -> Result<()> {
        self.tx(
            op::SET_PASSWORD,
            |w| {
                wire::put_account(w, account);
                put_password(w, password)
            },
            |_| Ok(()),
        )
    }

    pub(crate) fn add_identifier(&mut self, account: AccountId, identifier: &str) -> Result<()> {
        self.tx(
            op::ADD_IDENTIFIER,
            |w| {
                wire::put_account(w, account);
                put_str(w, identifier)
            },
            |_| Ok(()),
        )
    }

    pub(crate) fn remove_identifier(
        &mut self,
        account: AccountId,
        identifier: &str,
    ) -> Result<bool> {
        self.tx(
            op::REMOVE_IDENTIFIER,
            |w| {
                wire::put_account(w, account);
                put_str(w, identifier)
            },
            get_bool,
        )
    }

    pub(crate) fn define_role(&mut self, role: Role) -> Result<RoleId> {
        // Checked here as the engine checks it, so a role the wire cannot
        // carry fails the same way.
        role.check()?;
        self.tx(
            op::DEFINE_ROLE,
            |w| wire::put_role(w, &role),
            |r| Ok(RoleId::from_u32(r.u32()?)),
        )
    }

    pub(crate) fn assign_roles(&mut self, account: AccountId, roles: &[RoleId]) -> Result<()> {
        self.tx(
            op::ASSIGN_ROLES,
            |w| {
                wire::put_account(w, account);
                wire::put_roles(w, roles)
            },
            |_| Ok(()),
        )
    }

    pub(crate) fn new_recovery_codes(&mut self, account: AccountId) -> Result<RecoveryCodes> {
        self.account_op(op::NEW_RECOVERY_CODES, account, wire::get_codes)
    }

    pub(crate) fn use_recovery_code(&mut self, account: AccountId, code: &str) -> Result<bool> {
        self.tx(
            op::USE_RECOVERY_CODE,
            |w| {
                wire::put_account(w, account);
                put_str(w, code)
            },
            get_bool,
        )
    }

    pub(crate) fn create_api_key(
        &mut self,
        account: AccountId,
        scopes: &[&str],
        expiry: Option<SystemTime>,
    ) -> Result<ApiKey> {
        self.tx(
            op::CREATE_API_KEY,
            |w| {
                wire::put_account(w, account);
                w.u32(
                    u32::try_from(scopes.len())
                        .map_err(|_| Error::invalid("scopes", "at most 32"))?,
                );
                for scope in scopes {
                    put_str(w, scope)?;
                }
                wire::put_opt_time(w, expiry);
                Ok(())
            },
            wire::get_api_key,
        )
    }

    pub(crate) fn revoke_api_key(&mut self, id: ApiKeyId) -> Result<bool> {
        self.tx(
            op::REVOKE_API_KEY,
            |w| {
                w.bytes(&id.0);
                Ok(())
            },
            get_bool,
        )
    }

    pub(crate) fn revoke_session(&mut self, account: AccountId, id: SessionId) -> Result<bool> {
        self.tx(
            op::REVOKE_SESSION,
            |w| {
                wire::put_account(w, account);
                w.bytes(&id.0);
                Ok(())
            },
            get_bool,
        )
    }

    pub(crate) fn revoke(&mut self, token: &str) -> Result<bool> {
        self.tx(op::REVOKE, |w| put_str(w, token), get_bool)
    }

    pub(crate) fn retire_decoy(&mut self, token: &str) -> Result<bool> {
        self.tx(op::RETIRE_DECOY, |w| put_str(w, token), get_bool)
    }
}

#[cfg(feature = "mfa")]
impl RemoteStaged<'_> {
    pub(crate) fn add_totp(
        &mut self,
        account: AccountId,
    ) -> Result<crate::auth::totp::TotpEnrollment> {
        self.account_op(op::ADD_TOTP, account, wire::mfa::get_enrollment)
    }

    fn code_op(&mut self, op: u16, account: AccountId, code: &str) -> Result<bool> {
        self.tx(
            op,
            |w| {
                wire::put_account(w, account);
                put_str(w, code)
            },
            get_bool,
        )
    }

    pub(crate) fn confirm_totp(&mut self, account: AccountId, code: &str) -> Result<bool> {
        self.code_op(op::CONFIRM_TOTP, account, code)
    }

    pub(crate) fn check_totp(&mut self, account: AccountId, code: &str) -> Result<bool> {
        self.code_op(op::CHECK_TOTP, account, code)
    }

    pub(crate) fn remove_totp(&mut self, account: AccountId) -> Result<bool> {
        self.account_op(op::REMOVE_TOTP, account, get_bool)
    }

    pub(crate) fn passkey_registration(
        &mut self,
        account: AccountId,
    ) -> Result<crate::auth::passkey::PasskeyChallenge> {
        self.account_op(op::PASSKEY_REGISTRATION, account, wire::mfa::get_challenge)
    }

    pub(crate) fn passkey_sign_in(&mut self) -> Result<crate::auth::passkey::PasskeyChallenge> {
        self.tx(op::PASSKEY_SIGN_IN, |_| Ok(()), wire::mfa::get_challenge)
    }

    pub(crate) fn add_passkey(
        &mut self,
        account: AccountId,
        rp: &crate::auth::passkey::RelyingParty,
        registration: &crate::auth::passkey::PasskeyRegistration<'_>,
    ) -> Result<crate::auth::passkey::PasskeyId> {
        self.tx(
            op::ADD_PASSKEY,
            |w| {
                wire::put_account(w, account);
                wire::mfa::put_rp(w, rp)?;
                w.bytes32(registration.client_data_json)?;
                w.bytes32(registration.authenticator_data)
            },
            |r| Ok(crate::auth::passkey::PasskeyId(r.fixed()?)),
        )
    }

    pub(crate) fn remove_passkey(
        &mut self,
        account: AccountId,
        id: crate::auth::passkey::PasskeyId,
    ) -> Result<bool> {
        self.tx(
            op::REMOVE_PASSKEY,
            |w| {
                wire::put_account(w, account);
                w.bytes(&id.0);
                Ok(())
            },
            get_bool,
        )
    }

    pub(crate) fn complete_passkey(
        &mut self,
        rp: &crate::auth::passkey::RelyingParty,
        assertion: &crate::auth::passkey::PasskeyAssertion<'_>,
        spec: SessionSpec,
    ) -> Result<Option<crate::auth::PasskeyOutcome>> {
        self.tx(
            op::COMPLETE_PASSKEY,
            |w| {
                wire::mfa::put_rp(w, rp)?;
                w.bytes32(assertion.credential_id)?;
                w.bytes32(assertion.client_data_json)?;
                w.bytes32(assertion.authenticator_data)?;
                w.bytes32(assertion.signature)?;
                wire::put_spec(w, &spec)
            },
            wire::mfa::get_outcome,
        )
    }

    pub(crate) fn complete_second_factor(
        &mut self,
        challenge: &str,
        code: &str,
        spec: SessionSpec,
    ) -> Result<Option<(AccountId, Option<Token>)>> {
        self.tx(
            op::COMPLETE_SECOND_FACTOR,
            |w| {
                put_str(w, challenge)?;
                put_str(w, code)?;
                wire::put_spec(w, &spec)
            },
            wire::mfa::get_second,
        )
    }
}

/// A hashed password as an argument: the handle the auth process knows it
/// by, or (made by an embedded database) the hash itself.
fn put_password(w: &mut Writer<'_>, password: &HashedPassword) -> Result<()> {
    match &password.0 {
        Hashed::Phc(phc) => {
            w.u8(1);
            put_str(w, phc)
        }
        Hashed::Remote(handle) => {
            w.u8(2);
            w.bytes(&handle.id);
            Ok(())
        }
    }
}

impl Staged for RemoteStaged<'_> {
    fn engine(&self) -> EngineId {
        EngineId::AUTH
    }

    fn collection(&self) -> u32 {
        self.remote.collection
    }

    fn is_empty(&self) -> bool {
        self.empty
    }

    fn priority(&self) -> bool {
        self.priority
    }

    fn sealed(&self) -> bool {
        true
    }

    /// Kept for [`encode`](Self::encode), which checks and seals in one
    /// round trip.
    fn validate(&self, snapshot: Seq) -> std::result::Result<(), Conflict> {
        self.snapshot.store(snapshot, Ordering::Release);
        Ok(())
    }

    fn validate_reads(&self, snapshot: Seq) -> std::result::Result<(), Conflict> {
        if !self.serializable {
            return Ok(());
        }
        if !self.empty {
            // Checked with the sealing.
            self.check_reads.store(true, Ordering::Release);
            return Ok(());
        }
        if !self.touched {
            return Ok(());
        }
        // A part that only read gets no section: check here. An answer that
        // does not come counts as a conflict, so nothing unchecked lands.
        let (id, collection) = (self.id, self.remote.collection);
        let clear = self
            .remote
            .channel
            .request(op::TX_VALIDATE_READS, |w| {
                w.u64(id);
                w.u32(collection);
                w.u64(snapshot);
                Ok(())
            })
            .and_then(|reply| reply.decode(get_bool));
        match clear {
            Ok(true) => Ok(()),
            _ => Err(Conflict),
        }
    }

    /// Recorded by the auth process when it seals the section.
    fn reserve(&self, _seq: Seq) {}

    /// Check the writes (and reads, when serializable) against commits
    /// after the snapshot, seal the section for `seq`, and record the
    /// writes at `seq`: one round trip, inside the commit lock. A conflict
    /// comes back as [`Error::Conflict`], which the core retries.
    fn encode(&self, seq: Seq, out: &mut Vec<u8>) -> Result<()> {
        let (id, collection) = (self.id, self.remote.collection);
        let snapshot = self.snapshot.load(Ordering::Acquire);
        let reads = self.check_reads.load(Ordering::Acquire);
        let reply = self.remote.channel.request(op::TX_SEAL, |w| {
            w.u64(id);
            w.u32(collection);
            w.u64(snapshot);
            put_bool(w, reads);
            w.u64(seq);
            Ok(())
        })?;
        reply.decode(|r| {
            out.extend_from_slice(r.bytes32()?);
            Ok(())
        })
    }
}

impl Drop for RemoteStaged<'_> {
    fn drop(&mut self) {
        if self.touched {
            let id = self.id;
            self.remote.channel.send(op::TX_RELEASE, |w| {
                w.u64(id);
                Ok(())
            });
        }
    }
}
