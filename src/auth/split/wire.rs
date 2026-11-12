//! The channel's framing and the encoding of what crosses it.
//!
//! A request is `len u32 | id u64 | op u16 | payload` and a response
//! `len u32 | id u64 | status u8 | payload`, little-endian, where `len`
//! counts the bytes after itself. Id 0 marks a message that gets no
//! response. Payloads are built with the crate's [`Writer`] and read with
//! its [`Reader`], so every length is checked against the bytes there are.
//! A frame longer than [`MAX_FRAME`] is a framing error.

use std::{
    io::{self, Read},
    sync::{Mutex, PoisonError},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crypt_io::Zeroizing;

use super::super::{
    AccountView, Checked, Standing, decode_standing, encode_standing,
    keys::{ApiKey, ApiKeyCheck, ApiKeyId},
    recovery::RecoveryCodes,
    roles::{Role, RoleId},
    token::Token,
    types::{Purpose, RevokeReason, Session, SessionId, SessionInfo, SessionSpec, Validation},
};
use crate::{
    core::codec::{Reader, Writer},
    error::{Error, Result},
    feed::Change,
    ids::AccountId,
};

/// Longest frame: a log record (16 MiB) and room for its header.
pub(crate) const MAX_FRAME: usize = 16 * 1024 * 1024 + 4096;

/// Response status: the payload is the result.
pub(crate) const OK: u8 = 0;
/// Response status: the payload is an error.
pub(crate) const ERR: u8 = 1;

/// Bytes of a request header after the length: id and op.
pub(crate) const REQUEST_HEAD: usize = 10;
/// Bytes of a response header after the length: id and status.
pub(crate) const RESPONSE_HEAD: usize = 9;

/// What a reply's reader reports when it is malformed.
pub(crate) const REPLY: &str = "a message from the auth process";

/// Read one frame (the bytes after its length). `Ok(None)` when the stream
/// ends before a frame starts.
pub(crate) fn read_frame(input: &mut impl Read, head: usize) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < len.len() {
        match input.read(&mut len[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let len = u32::from_le_bytes(len) as usize;
    if len < head || len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame length"));
    }
    let mut frame = vec![0u8; len];
    input.read_exact(&mut frame)?;
    Ok(Some(frame))
}

/// A frame: `len`, then `head` (id and op, or id and status), then what `f`
/// writes.
pub(crate) fn frame(
    head: impl FnOnce(&mut Writer<'_>),
    f: impl FnOnce(&mut Writer<'_>) -> Result<()>,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(64);
    let mut w = Writer::new(&mut out);
    w.u32(0);
    head(&mut w);
    f(&mut w)?;
    let len = out.len() - 4;
    if len > MAX_FRAME {
        return Err(Error::invalid("commit", "larger than 16 MiB"));
    }
    let len = u32::try_from(len).map_err(|_| Error::invalid("commit", "larger than 16 MiB"))?;
    out[..4].copy_from_slice(&len.to_le_bytes());
    Ok(out)
}

// Strings and bytes: a u32 length, so no input is cut short by the wire.

pub(crate) fn put_str(w: &mut Writer<'_>, s: &str) -> Result<()> {
    w.bytes32(s.as_bytes())
}

pub(crate) fn get_str<'a>(r: &mut Reader<'a>) -> Result<&'a str> {
    std::str::from_utf8(r.bytes32()?).map_err(|_| Error::corrupt(REPLY, 0))
}

pub(crate) fn put_bool(w: &mut Writer<'_>, b: bool) {
    w.u8(u8::from(b));
}

pub(crate) fn get_bool(r: &mut Reader<'_>) -> Result<bool> {
    match r.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::corrupt(REPLY, 0)),
    }
}

pub(crate) fn put_account(w: &mut Writer<'_>, account: AccountId) {
    w.bytes(account.as_bytes());
}

pub(crate) fn get_account(r: &mut Reader<'_>) -> Result<AccountId> {
    Ok(AccountId::from_bytes(r.fixed()?))
}

pub(crate) fn put_opt_account(w: &mut Writer<'_>, account: Option<AccountId>) {
    match account {
        Some(account) => {
            w.u8(1);
            put_account(w, account);
        }
        None => w.u8(0),
    }
}

pub(crate) fn get_opt_account(r: &mut Reader<'_>) -> Result<Option<AccountId>> {
    Ok(if get_bool(r)? {
        Some(get_account(r)?)
    } else {
        None
    })
}

pub(crate) fn put_token(w: &mut Writer<'_>, token: &Token) -> Result<()> {
    w.str16(token.as_str())
}

pub(crate) fn get_token(r: &mut Reader<'_>) -> Result<Token> {
    Token::from_text(r.str16()?.to_owned()).ok_or_else(|| Error::corrupt(REPLY, 0))
}

pub(crate) fn put_duration(w: &mut Writer<'_>, d: Duration) {
    w.u64(d.as_secs());
    w.u32(d.subsec_nanos());
}

pub(crate) fn get_duration(r: &mut Reader<'_>) -> Result<Duration> {
    let secs = r.u64()?;
    let nanos = r.u32()?;
    if nanos >= 1_000_000_000 {
        return Err(Error::corrupt(REPLY, 0));
    }
    Ok(Duration::new(secs, nanos))
}

fn put_opt_duration(w: &mut Writer<'_>, d: Option<Duration>) {
    match d {
        Some(d) => {
            w.u8(1);
            put_duration(w, d);
        }
        None => w.u8(0),
    }
}

fn get_opt_duration(r: &mut Reader<'_>) -> Result<Option<Duration>> {
    Ok(if get_bool(r)? {
        Some(get_duration(r)?)
    } else {
        None
    })
}

/// A time, before or after the Unix epoch, to the nanosecond.
pub(crate) fn put_time(w: &mut Writer<'_>, t: SystemTime) {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            w.u8(1);
            put_duration(w, d);
        }
        Err(e) => {
            w.u8(2);
            put_duration(w, e.duration());
        }
    }
}

pub(crate) fn get_time(r: &mut Reader<'_>) -> Result<SystemTime> {
    let tag = r.u8()?;
    let d = get_duration(r)?;
    let t = match tag {
        1 => UNIX_EPOCH.checked_add(d),
        2 => UNIX_EPOCH.checked_sub(d),
        _ => None,
    };
    t.ok_or_else(|| Error::corrupt(REPLY, 0))
}

pub(crate) fn put_opt_time(w: &mut Writer<'_>, t: Option<SystemTime>) {
    match t {
        Some(t) => put_time(w, t),
        None => w.u8(0),
    }
}

pub(crate) fn get_opt_time(r: &mut Reader<'_>) -> Result<Option<SystemTime>> {
    // A tag of 0 is no time; others are read by `get_time`.
    let peek = r.u8()?;
    if peek == 0 {
        return Ok(None);
    }
    let d = get_duration(r)?;
    let t = match peek {
        1 => UNIX_EPOCH.checked_add(d),
        2 => UNIX_EPOCH.checked_sub(d),
        _ => None,
    };
    t.map(Some).ok_or_else(|| Error::corrupt(REPLY, 0))
}

pub(crate) fn put_spec(w: &mut Writer<'_>, spec: &SessionSpec) -> Result<()> {
    let (idle, recheck) = spec.limits();
    put_duration(w, spec.ttl());
    put_opt_duration(w, idle);
    put_opt_duration(w, recheck);
    w.bytes16(spec.payload_bytes())
}

pub(crate) fn get_spec(r: &mut Reader<'_>) -> Result<SessionSpec> {
    let ttl = get_duration(r)?;
    let idle = get_opt_duration(r)?;
    let recheck = get_opt_duration(r)?;
    SessionSpec::from_parts(ttl, idle, recheck, r.bytes16()?)
}

pub(crate) fn put_purpose(w: &mut Writer<'_>, purpose: Purpose) {
    let (kind, code) = match purpose {
        Purpose::VerifyEmail => (1, 0),
        Purpose::ResetPassword => (2, 0),
        Purpose::SignInLink => (3, 0),
        Purpose::Preview => (4, 0),
        Purpose::Custom(code) => (5, code),
    };
    w.u8(kind);
    w.u16(code);
}

pub(crate) fn get_purpose(r: &mut Reader<'_>) -> Result<Purpose> {
    let kind = r.u8()?;
    let code = r.u16()?;
    Ok(match kind {
        1 => Purpose::VerifyEmail,
        2 => Purpose::ResetPassword,
        3 => Purpose::SignInLink,
        4 => Purpose::Preview,
        5 => Purpose::Custom(code),
        _ => return Err(Error::corrupt(REPLY, 0)),
    })
}

pub(crate) fn put_standing(w: &mut Writer<'_>, standing: Standing) {
    let (code, until, reason) = encode_standing(standing);
    w.u8(code);
    w.u64(until);
    w.u32(reason);
}

pub(crate) fn get_standing(r: &mut Reader<'_>) -> Result<Standing> {
    let code = r.u8()?;
    let until = r.u64()?;
    let reason = r.u32()?;
    decode_standing(code, until, reason).map_err(|_| Error::corrupt(REPLY, 0))
}

pub(crate) fn put_roles(w: &mut Writer<'_>, roles: &[RoleId]) -> Result<()> {
    w.u32(u32::try_from(roles.len()).map_err(|_| Error::invalid("roles", "too many"))?);
    for role in roles {
        w.u32(role.get());
    }
    Ok(())
}

pub(crate) fn get_roles(r: &mut Reader<'_>) -> Result<Vec<RoleId>> {
    let n = r.u32()? as usize;
    // Each id takes four bytes: a count the bytes cannot hold is refused
    // before anything is reserved.
    let mut roles = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        roles.push(RoleId::from_u32(r.u32()?));
    }
    Ok(roles)
}

pub(crate) fn put_role(w: &mut Writer<'_>, role: &Role) -> Result<()> {
    put_str(w, &role.name)?;
    w.u32(u32::try_from(role.permissions.len()).map_err(|_| Error::invalid("role", "too large"))?);
    for p in &role.permissions {
        put_str(w, p)?;
    }
    put_roles(w, &role.inherits)
}

pub(crate) fn get_role(r: &mut Reader<'_>) -> Result<Role> {
    let name = get_str(r)?.to_owned();
    let n = r.u32()? as usize;
    let mut permissions = Vec::with_capacity(n.min(64));
    for _ in 0..n {
        permissions.push(get_str(r)?.to_owned());
    }
    let inherits = get_roles(r)?;
    Ok(Role {
        name,
        permissions,
        inherits,
    })
}

pub(crate) fn put_session(w: &mut Writer<'_>, s: &Session) -> Result<()> {
    put_account(w, s.account);
    w.u64(s.created_ms);
    w.u64(s.expires_ms);
    w.u32(s.epoch);
    w.u64(s.idle_ms);
    w.u64(s.recheck_ms);
    w.bytes16(s.payload.as_bytes())
}

pub(crate) fn get_session(r: &mut Reader<'_>) -> Result<Session> {
    Ok(Session {
        account: get_account(r)?,
        created_ms: r.u64()?,
        expires_ms: r.u64()?,
        epoch: r.u32()?,
        idle_ms: r.u64()?,
        recheck_ms: r.u64()?,
        payload: super::super::types::Payload::new(r.bytes16()?)
            .map_err(|_| Error::corrupt(REPLY, 0))?,
    })
}

fn put_reason(w: &mut Writer<'_>, reason: RevokeReason) {
    w.u8(match reason {
        RevokeReason::Revoked => 1,
        RevokeReason::Rotated => 2,
        RevokeReason::SignedOutEverywhere => 3,
        RevokeReason::Erased => 4,
    });
}

fn get_reason(r: &mut Reader<'_>) -> Result<RevokeReason> {
    Ok(match r.u8()? {
        1 => RevokeReason::Revoked,
        2 => RevokeReason::Rotated,
        3 => RevokeReason::SignedOutEverywhere,
        4 => RevokeReason::Erased,
        _ => return Err(Error::corrupt(REPLY, 0)),
    })
}

pub(crate) fn put_validation(w: &mut Writer<'_>, v: &Validation) -> Result<()> {
    match v {
        Validation::Valid(session) => {
            w.u8(1);
            put_session(w, session)?;
        }
        Validation::Expired => w.u8(2),
        Validation::Revoked { reason } => {
            w.u8(3);
            put_reason(w, *reason);
        }
        Validation::Unknown => w.u8(4),
        Validation::Malformed => w.u8(5),
    }
    Ok(())
}

/// A validation reply: as [`put_validation`], with a decoy as its own code
/// so the application raises the event.
pub(crate) fn put_checked_validation(
    w: &mut Writer<'_>,
    v: &Validation,
    decoy: bool,
) -> Result<()> {
    if decoy {
        w.u8(6);
        return Ok(());
    }
    put_validation(w, v)
}

/// A validation reply and whether the token was a decoy.
pub(crate) fn get_checked_validation(r: &mut Reader<'_>) -> Result<(Validation, bool)> {
    match r.u8()? {
        6 => Ok((Validation::Unknown, true)),
        code => Ok((validation_of(code, r)?, false)),
    }
}

fn validation_of(code: u8, r: &mut Reader<'_>) -> Result<Validation> {
    Ok(match code {
        1 => Validation::Valid(get_session(r)?),
        2 => Validation::Expired,
        3 => Validation::Revoked {
            reason: get_reason(r)?,
        },
        4 => Validation::Unknown,
        5 => Validation::Malformed,
        _ => return Err(Error::corrupt(REPLY, 0)),
    })
}

pub(crate) fn put_checked(w: &mut Writer<'_>, c: &Checked) {
    match c {
        Checked::Verified(account) => {
            w.u8(1);
            put_account(w, *account);
        }
        Checked::Wrong(account) => {
            w.u8(2);
            put_opt_account(w, *account);
        }
        Checked::Blocked(until) => {
            w.u8(3);
            put_opt_time(w, *until);
        }
    }
}

pub(crate) fn get_checked(r: &mut Reader<'_>) -> Result<Checked> {
    Ok(match r.u8()? {
        1 => Checked::Verified(get_account(r)?),
        2 => Checked::Wrong(get_opt_account(r)?),
        3 => Checked::Blocked(get_opt_time(r)?),
        _ => return Err(Error::corrupt(REPLY, 0)),
    })
}

pub(crate) fn put_view(w: &mut Writer<'_>, view: Option<&AccountView>) -> Result<()> {
    match view {
        Some(view) => {
            w.u8(1);
            w.u64(view.created_ms);
            put_standing(w, view.standing);
            put_roles(w, &view.roles)?;
        }
        None => w.u8(0),
    }
    Ok(())
}

pub(crate) fn get_view(r: &mut Reader<'_>) -> Result<Option<AccountView>> {
    if !get_bool(r)? {
        return Ok(None);
    }
    Ok(Some(AccountView {
        created_ms: r.u64()?,
        standing: get_standing(r)?,
        roles: get_roles(r)?,
    }))
}

pub(crate) fn put_session_infos(w: &mut Writer<'_>, infos: &[SessionInfo]) -> Result<()> {
    w.u32(u32::try_from(infos.len()).map_err(|_| Error::invalid("sessions", "too many"))?);
    for info in infos {
        w.bytes(&info.id.0);
        w.u64(info.created_ms);
        w.u64(info.expires_ms);
        w.u64(info.last_used_ms);
        w.u64(info.idle_ms);
    }
    Ok(())
}

pub(crate) fn get_session_infos(r: &mut Reader<'_>) -> Result<Vec<SessionInfo>> {
    let n = r.u32()? as usize;
    let mut out = Vec::with_capacity(n.min(4096));
    for _ in 0..n {
        out.push(SessionInfo {
            id: SessionId(r.fixed()?),
            created_ms: r.u64()?,
            expires_ms: r.u64()?,
            last_used_ms: r.u64()?,
            idle_ms: r.u64()?,
        });
    }
    Ok(out)
}

pub(crate) fn put_key_check(w: &mut Writer<'_>, check: &ApiKeyCheck) -> Result<()> {
    match check {
        ApiKeyCheck::Valid {
            account,
            id,
            scopes,
        } => {
            w.u8(1);
            put_account(w, *account);
            w.bytes(&id.0);
            w.u32(u32::try_from(scopes.len()).map_err(|_| Error::invalid("scopes", "too many"))?);
            for scope in scopes {
                put_str(w, scope)?;
            }
        }
        ApiKeyCheck::Expired => w.u8(2),
        ApiKeyCheck::Revoked => w.u8(3),
        ApiKeyCheck::Unknown => w.u8(4),
        ApiKeyCheck::Malformed => w.u8(5),
    }
    Ok(())
}

pub(crate) fn get_key_check(r: &mut Reader<'_>) -> Result<ApiKeyCheck> {
    Ok(match r.u8()? {
        1 => {
            let account = get_account(r)?;
            let id = ApiKeyId(r.fixed()?);
            let n = r.u32()? as usize;
            let mut scopes = Vec::with_capacity(n.min(32));
            for _ in 0..n {
                scopes.push(get_str(r)?.to_owned());
            }
            ApiKeyCheck::Valid {
                account,
                id,
                scopes,
            }
        }
        2 => ApiKeyCheck::Expired,
        3 => ApiKeyCheck::Revoked,
        4 => ApiKeyCheck::Unknown,
        5 => ApiKeyCheck::Malformed,
        _ => return Err(Error::corrupt(REPLY, 0)),
    })
}

pub(crate) fn put_api_key(w: &mut Writer<'_>, key: &ApiKey) -> Result<()> {
    w.bytes(&key.id.0);
    put_token(w, &key.token)
}

pub(crate) fn get_api_key(r: &mut Reader<'_>) -> Result<ApiKey> {
    Ok(ApiKey {
        id: ApiKeyId(r.fixed()?),
        token: get_token(r)?,
    })
}

pub(crate) fn put_codes(w: &mut Writer<'_>, codes: &RecoveryCodes) -> Result<()> {
    w.u32(u32::try_from(codes.codes.len()).map_err(|_| Error::invalid("codes", "too many"))?);
    for code in &codes.codes {
        w.str16(code)?;
    }
    Ok(())
}

pub(crate) fn get_codes(r: &mut Reader<'_>) -> Result<RecoveryCodes> {
    let n = r.u32()? as usize;
    let mut codes = Vec::with_capacity(n.min(16));
    for _ in 0..n {
        codes.push(Zeroizing::new(r.str16()?.to_owned()));
    }
    Ok(RecoveryCodes { codes })
}

pub(crate) fn put_change(w: &mut Writer<'_>, change: &Change) -> Result<()> {
    match change {
        Change::AccountCreated { account } => {
            w.u8(1);
            put_account(w, *account);
        }
        Change::SessionRevoked { account } => {
            w.u8(2);
            put_opt_account(w, *account);
        }
        Change::StandingChanged { account } => {
            w.u8(3);
            put_account(w, *account);
        }
        Change::AccountChanged { account } => {
            w.u8(4);
            put_account(w, *account);
        }
        Change::AccountErased { account } => {
            w.u8(5);
            put_account(w, *account);
        }
        _ => return Err(Error::invalid("change", "not one the auth engine makes")),
    }
    Ok(())
}

pub(crate) fn get_change(r: &mut Reader<'_>) -> Result<Change> {
    Ok(match r.u8()? {
        1 => Change::AccountCreated {
            account: get_account(r)?,
        },
        2 => Change::SessionRevoked {
            account: get_opt_account(r)?,
        },
        3 => Change::StandingChanged {
            account: get_account(r)?,
        },
        4 => Change::AccountChanged {
            account: get_account(r)?,
        },
        5 => Change::AccountErased {
            account: get_account(r)?,
        },
        _ => return Err(Error::corrupt(REPLY, 0)),
    })
}

#[cfg(feature = "mfa")]
pub(crate) mod mfa {
    //! The second-factor values.

    use crypt_io::Zeroizing;

    use super::{
        Error, Reader, Result, Token, Writer, get_account, get_bool, get_opt_time, get_str,
        get_token, put_account, put_opt_time, put_str, put_token,
    };
    use crate::auth::{
        PasskeyOutcome,
        passkey::{PasskeyChallenge, PasskeyId, PasskeyInfo, RelyingParty},
        totp::{SECRET_LEN, TotpEnrollment},
    };

    pub(crate) fn put_rp(w: &mut Writer<'_>, rp: &RelyingParty) -> Result<()> {
        put_str(w, &rp.id)?;
        w.u32(u32::try_from(rp.origins.len()).map_err(|_| Error::invalid("origins", "too many"))?);
        for origin in &rp.origins {
            put_str(w, origin)?;
        }
        w.u8(u8::from(rp.user_verification));
        Ok(())
    }

    pub(crate) fn get_rp(r: &mut Reader<'_>) -> Result<RelyingParty> {
        let id = get_str(r)?.to_owned();
        let n = r.u32()? as usize;
        let mut origins = Vec::with_capacity(n.min(16));
        for _ in 0..n {
            origins.push(get_str(r)?.to_owned());
        }
        Ok(RelyingParty {
            id,
            origins,
            user_verification: get_bool(r)?,
        })
    }

    pub(crate) fn put_enrollment(w: &mut Writer<'_>, e: &TotpEnrollment) {
        w.bytes(&e.secret[..]);
    }

    pub(crate) fn get_enrollment(r: &mut Reader<'_>) -> Result<TotpEnrollment> {
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        secret.copy_from_slice(r.take(SECRET_LEN)?);
        Ok(TotpEnrollment { secret })
    }

    pub(crate) fn put_challenge(w: &mut Writer<'_>, c: &PasskeyChallenge) {
        w.bytes(&c.bytes[..]);
    }

    pub(crate) fn get_challenge(r: &mut Reader<'_>) -> Result<PasskeyChallenge> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(r.take(32)?);
        Ok(PasskeyChallenge { bytes })
    }

    pub(crate) fn put_passkey_infos(w: &mut Writer<'_>, infos: &[PasskeyInfo]) -> Result<()> {
        w.u32(u32::try_from(infos.len()).map_err(|_| Error::invalid("passkeys", "too many"))?);
        for info in infos {
            w.bytes(&info.id.0);
            w.u64(info.created_ms);
            w.u64(info.last_used_ms);
        }
        Ok(())
    }

    pub(crate) fn get_passkey_infos(r: &mut Reader<'_>) -> Result<Vec<PasskeyInfo>> {
        let n = r.u32()? as usize;
        let mut out = Vec::with_capacity(n.min(256));
        for _ in 0..n {
            out.push(PasskeyInfo {
                id: PasskeyId(r.fixed()?),
                created_ms: r.u64()?,
                last_used_ms: r.u64()?,
            });
        }
        Ok(out)
    }

    pub(crate) fn put_outcome(w: &mut Writer<'_>, outcome: &Option<PasskeyOutcome>) -> Result<()> {
        match outcome {
            None => w.u8(0),
            Some(Ok((account, token))) => {
                w.u8(1);
                put_account(w, *account);
                put_token(w, token)?;
            }
            Some(Err(until)) => {
                w.u8(2);
                put_opt_time(w, *until);
            }
        }
        Ok(())
    }

    pub(crate) fn get_outcome(r: &mut Reader<'_>) -> Result<Option<PasskeyOutcome>> {
        Ok(match r.u8()? {
            0 => None,
            1 => Some(Ok((get_account(r)?, get_token(r)?))),
            2 => Some(Err(get_opt_time(r)?)),
            _ => return Err(Error::corrupt(super::REPLY, 0)),
        })
    }

    pub(crate) fn put_second(
        w: &mut Writer<'_>,
        outcome: &Option<(crate::ids::AccountId, Option<Token>)>,
    ) -> Result<()> {
        match outcome {
            None => w.u8(0),
            Some((account, token)) => {
                w.u8(1);
                put_account(w, *account);
                match token {
                    Some(token) => {
                        w.u8(1);
                        put_token(w, token)?;
                    }
                    None => w.u8(0),
                }
            }
        }
        Ok(())
    }

    pub(crate) fn get_second(
        r: &mut Reader<'_>,
    ) -> Result<Option<(crate::ids::AccountId, Option<Token>)>> {
        if !get_bool(r)? {
            return Ok(None);
        }
        let account = get_account(r)?;
        let token = if get_bool(r)? {
            Some(get_token(r)?)
        } else {
            None
        };
        Ok(Some((account, token)))
    }
}

// Errors cross as their variant and fields. A variant's text fields are
// `&'static str`; received ones are kept in a bounded table, so a process
// that sends ever new text cannot grow this one's memory.

/// Most distinct texts kept from received errors.
const MAX_INTERNED: usize = 512;
/// Longest text kept from a received error, in bytes.
const MAX_TEXT: usize = 200;
/// The text used past those bounds.
const FALLBACK: &str = "a value the auth process named";
/// Longest message of a received storage error's source, in bytes.
const MAX_SOURCE: usize = 512;

static INTERNED: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());

/// `text` as a `&'static str`: one kept before, or a new one while there is
/// room, or [`FALLBACK`].
fn intern(text: &str) -> &'static str {
    intern_in(&INTERNED, text)
}

/// [`intern`] with the table `table`.
fn intern_in(table: &Mutex<Vec<&'static str>>, text: &str) -> &'static str {
    if text.len() > MAX_TEXT {
        return FALLBACK;
    }
    let mut kept = table.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(found) = kept.iter().find(|k| **k == text) {
        return found;
    }
    if kept.len() >= MAX_INTERNED {
        return FALLBACK;
    }
    let leaked: &'static str = Box::leak(text.to_owned().into_boxed_str());
    kept.push(leaked);
    leaked
}

/// `text` cut to at most `max` bytes, at a character boundary.
fn cut(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn put_text(w: &mut Writer<'_>, text: &str) {
    // A cut text always fits a u16 length.
    let text = cut(text, MAX_SOURCE);
    w.u16(text.len() as u16);
    w.bytes(text.as_bytes());
}

pub(crate) fn put_error(w: &mut Writer<'_>, err: &Error) {
    match err {
        Error::AlreadyExists { what } => {
            w.u8(1);
            put_text(w, what);
        }
        Error::Conflict => w.u8(2),
        Error::Busy { what } => {
            w.u8(3);
            put_text(w, what);
        }
        Error::Invalid { field, reason } => {
            w.u8(4);
            put_text(w, field);
            put_text(w, reason);
        }
        Error::KeyUnavailable => w.u8(5),
        Error::Locked => w.u8(6),
        Error::Corrupt { what, at } => {
            w.u8(7);
            put_text(w, what);
            w.u64(*at);
        }
        Error::Storage { what, source } => {
            w.u8(8);
            put_text(w, what);
            put_text(w, &source.to_string());
        }
        Error::SnapshotTooOld => w.u8(9),
        Error::Restricted { what } => {
            w.u8(10);
            put_text(w, what);
        }
        Error::FeedBehind { oldest } => {
            w.u8(11);
            w.u64(*oldest);
        }
        Error::ReadOnlyReplica => w.u8(12),
        Error::ReplicaBehind { oldest } => {
            w.u8(13);
            w.u64(*oldest);
        }
    }
}

/// The error a reply carries. A malformed one is itself an error, so the
/// call fails either way.
pub(crate) fn get_error(r: &mut Reader<'_>) -> Error {
    match read_error(r) {
        Ok(err) => err,
        Err(err) => malformed(err),
    }
}

/// A reply that does not decode is the channel's failure, not damage to
/// stored data: [`Error::Storage`]. Other errors pass through.
pub(crate) fn malformed(err: Error) -> Error {
    match err {
        Error::Corrupt { what, .. } if what == REPLY => Error::storage(
            "reading a reply from the auth process",
            "the reply is malformed",
        ),
        err => err,
    }
}

fn read_error(r: &mut Reader<'_>) -> Result<Error> {
    let text = |r: &mut Reader<'_>| -> Result<&'static str> { Ok(intern(r.str16()?)) };
    let err = match r.u8()? {
        1 => Error::AlreadyExists { what: text(r)? },
        2 => Error::Conflict,
        3 => Error::Busy { what: text(r)? },
        4 => Error::Invalid {
            field: text(r)?,
            reason: text(r)?,
        },
        5 => Error::KeyUnavailable,
        6 => Error::Locked,
        7 => Error::Corrupt {
            what: text(r)?,
            at: r.u64()?,
        },
        8 => {
            let what = text(r)?;
            let source = cut(r.str16()?, MAX_SOURCE).to_owned();
            Error::storage(what, source)
        }
        9 => Error::SnapshotTooOld,
        10 => Error::Restricted { what: text(r)? },
        11 => Error::FeedBehind { oldest: r.u64()? },
        12 => Error::ReadOnlyReplica,
        13 => Error::ReplicaBehind { oldest: r.u64()? },
        _ => return Err(Error::corrupt(REPLY, 0)),
    };
    r.finish()?;
    Ok(err)
}

/// Runs this module's decoders on `data`, for fuzzing and tests. Errors are
/// expected; a panic, a hang, or an allocation the input asked for is a bug.
#[cfg(any(fuzzing, test))]
pub(crate) fn fuzz(data: &[u8]) {
    let _ = read_frame(&mut &data[..], REQUEST_HEAD);
    let _ = read_frame(&mut &data[..], RESPONSE_HEAD);
    // Every reader the application uses on a reply, from the start.
    let reader = || Reader::new(data, "fuzz", 0);
    let _ = get_bool(&mut reader());
    let _ = get_account(&mut reader());
    let _ = get_opt_account(&mut reader());
    let _ = get_token(&mut reader());
    let _ = get_duration(&mut reader());
    let _ = get_time(&mut reader());
    let _ = get_opt_time(&mut reader());
    let _ = get_spec(&mut reader());
    let _ = get_purpose(&mut reader());
    let _ = get_standing(&mut reader());
    let _ = get_roles(&mut reader());
    let _ = get_role(&mut reader());
    let _ = get_session(&mut reader());
    let _ = get_checked_validation(&mut reader());
    let _ = get_checked(&mut reader());
    let _ = get_view(&mut reader());
    let _ = get_session_infos(&mut reader());
    let _ = get_key_check(&mut reader());
    let _ = get_api_key(&mut reader());
    let _ = get_codes(&mut reader());
    let _ = get_change(&mut reader());
    let _ = get_error(&mut reader());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round(err: &Error) -> Error {
        let mut out = Vec::new();
        put_error(&mut Writer::new(&mut out), err);
        get_error(&mut Reader::new(&out, REPLY, 0))
    }

    #[test]
    fn test_errors_round_trip_with_their_fields() {
        assert!(matches!(
            round(&Error::invalid("password", "must be 1 to 1024 bytes")),
            Error::Invalid {
                field: "password",
                reason: "must be 1 to 1024 bytes"
            }
        ));
        assert!(matches!(round(&Error::Conflict), Error::Conflict));
        assert!(matches!(
            round(&Error::corrupt("a sealed auth section", 7)),
            Error::Corrupt { at: 7, .. }
        ));
        let storage = round(&Error::storage("syncing", "disk gone"));
        assert!(storage.to_string().contains("disk gone"));
        assert!(matches!(
            round(&Error::ReadOnlyReplica),
            Error::ReadOnlyReplica
        ));
        assert!(matches!(
            round(&Error::ReplicaBehind { oldest: 9 }),
            Error::ReplicaBehind { oldest: 9 }
        ));
    }

    #[test]
    fn test_interned_texts_are_bounded() {
        // A table of its own: filling the shared one would change what
        // tests running alongside receive.
        let table = Mutex::new(Vec::new());
        let long = "x".repeat(MAX_TEXT + 1);
        assert_eq!(intern_in(&table, &long), FALLBACK);
        for i in 0..MAX_INTERNED + 10 {
            let _ = intern_in(&table, &format!("text {i}"));
        }
        assert!(table.lock().unwrap().len() <= MAX_INTERNED);
        assert_eq!(
            intern_in(&table, "a text never seen before, past the bound"),
            FALLBACK
        );
        assert_eq!(intern_in(&table, "text 3"), "text 3");
    }

    #[test]
    fn test_malformed_error_is_an_error_not_a_panic() {
        let err = get_error(&mut Reader::new(&[99], REPLY, 0));
        assert!(matches!(err, Error::Storage { .. }));
        let err = get_error(&mut Reader::new(&[4, 200, 0], REPLY, 0));
        assert!(matches!(err, Error::Storage { .. }));
    }

    #[test]
    fn test_frame_length_bounds_are_checked() {
        let mut short = &[3u8, 0, 0, 0, 1, 2, 3][..];
        assert!(read_frame(&mut short, REQUEST_HEAD).is_err());
        let mut huge = &u32::MAX.to_le_bytes()[..];
        assert!(read_frame(&mut huge, REQUEST_HEAD).is_err());
        let mut empty = &[][..];
        assert!(read_frame(&mut empty, REQUEST_HEAD).unwrap().is_none());
        let mut cut = &[20u8, 0][..];
        assert!(read_frame(&mut cut, REQUEST_HEAD).is_err());
    }

    #[test]
    fn test_validation_and_spec_round_trip() {
        let spec = SessionSpec::new(Duration::from_millis(1500))
            .unwrap()
            .idle(Duration::from_secs(9))
            .payload(b"p")
            .unwrap();
        let mut out = Vec::new();
        put_spec(&mut Writer::new(&mut out), &spec).unwrap();
        assert_eq!(get_spec(&mut Reader::new(&out, REPLY, 0)).unwrap(), spec);
        for v in [
            Validation::Expired,
            Validation::Unknown,
            Validation::Malformed,
            Validation::Revoked {
                reason: RevokeReason::Erased,
            },
        ] {
            for decoy in [false, true] {
                let mut out = Vec::new();
                put_checked_validation(&mut Writer::new(&mut out), &v, decoy).unwrap();
                let back = get_checked_validation(&mut Reader::new(&out, REPLY, 0)).unwrap();
                // A decoy always reads back as Unknown, flagged.
                let expect = if decoy { Validation::Unknown } else { v };
                assert_eq!(back, (expect, decoy));
            }
        }
    }
}
