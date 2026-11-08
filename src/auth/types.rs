//! The auth engine's public value types.

use std::{
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::token::Token;
use crate::{
    error::{Error, Result},
    ids::AccountId,
};

/// Longest session lifetime accepted: 400 days.
const MAX_TTL: Duration = Duration::from_secs(400 * 24 * 60 * 60);

/// Largest session payload, in bytes.
pub(crate) const MAX_PAYLOAD: usize = 256;

/// How a new session behaves.
///
/// ```
/// use std::time::Duration;
/// use nex_db::SessionSpec;
///
/// let web = SessionSpec::web();
/// assert_eq!(web.ttl(), Duration::from_secs(30 * 24 * 60 * 60));
/// let short = SessionSpec::new(Duration::from_secs(3600))?
///     .idle(Duration::from_secs(900))
///     .recheck_after(Duration::from_secs(300))
///     .payload(b"role=editor")?;
/// assert_eq!(short.ttl(), Duration::from_secs(3600));
/// assert!(SessionSpec::new(Duration::ZERO).is_err());
/// assert!(SessionSpec::web().payload(&[0; 257]).is_err());
/// # Ok::<(), nex_db::Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionSpec {
    ttl: Duration,
    idle: Option<Duration>,
    recheck: Option<Duration>,
    payload: Payload,
}

impl fmt::Debug for SessionSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionSpec")
            .field("ttl", &self.ttl)
            .field("idle", &self.idle)
            .field("recheck", &self.recheck)
            .field("payload_len", &self.payload.len)
            .finish()
    }
}

impl SessionSpec {
    /// A browser session: valid for 30 days from issue.
    #[must_use]
    pub const fn web() -> Self {
        SessionSpec {
            ttl: Duration::from_secs(30 * 24 * 60 * 60),
            idle: None,
            recheck: None,
            payload: Payload::EMPTY,
        }
    }

    /// End the session when it goes unused for `limit` (a validation counts
    /// as use). `Duration::ZERO` means no idle limit. Use is remembered in
    /// memory and saved by each checkpoint, so after a crash an idle session
    /// may end up to one checkpoint early or late.
    #[must_use]
    pub const fn idle(mut self, limit: Duration) -> Self {
        self.idle = if limit.is_zero() { None } else { Some(limit) };
        self
    }

    /// Ask the application to check the account again (its standing, its
    /// roles) once `after` has passed since issue: [`Session::recheck_at`]
    /// says when. nex-db does nothing at that time itself.
    #[must_use]
    pub const fn recheck_after(mut self, after: Duration) -> Self {
        self.recheck = Some(after);
        self
    }

    /// Up to 256 bytes stored with the session and returned with every
    /// validation (permissions, attributes). Opaque to nex-db, and not a
    /// secret: it is held unencrypted in memory, like the rest of the
    /// session.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when `bytes` is longer than 256 bytes.
    pub fn payload(mut self, bytes: &[u8]) -> Result<Self> {
        self.payload = Payload::new(bytes)?;
        Ok(self)
    }

    pub(crate) fn idle_ms(&self) -> u64 {
        self.idle.map_or(0, |d| {
            u64::try_from(d.as_millis()).unwrap_or(u64::MAX).max(1)
        })
    }

    pub(crate) fn recheck_ms(&self) -> Option<u64> {
        self.recheck
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }

    pub(crate) fn payload_bytes(&self) -> &[u8] {
        self.payload.as_bytes()
    }

    /// A session valid for `ttl` from issue.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when `ttl` is zero or longer than 400 days.
    pub fn new(ttl: Duration) -> Result<Self> {
        if ttl.is_zero() || ttl > MAX_TTL {
            return Err(Error::invalid(
                "session lifetime",
                "must be 1 ms to 400 days",
            ));
        }
        Ok(SessionSpec {
            ttl,
            ..SessionSpec::web()
        })
    }

    /// How long the session stays valid after issue.
    #[must_use]
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }

    pub(crate) fn ttl_ms(&self) -> u64 {
        u64::try_from(self.ttl.as_millis()).unwrap_or(u64::MAX)
    }
}

/// Up to [`MAX_PAYLOAD`] bytes, inline.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Payload {
    len: u16,
    bytes: [u8; MAX_PAYLOAD],
}

impl Payload {
    pub(crate) const EMPTY: Payload = Payload {
        len: 0,
        bytes: [0; MAX_PAYLOAD],
    };

    pub(crate) fn new(bytes: &[u8]) -> Result<Payload> {
        if bytes.len() > MAX_PAYLOAD {
            return Err(Error::invalid("session payload", "longer than 256 bytes"));
        }
        let mut payload = Payload::EMPTY;
        payload.bytes[..bytes.len()].copy_from_slice(bytes);
        payload.len = bytes.len() as u16;
        Ok(payload)
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// A payload of the first `len` bytes of `bytes`; the bytes after them
    /// must be zero. `None` if `len` is too long.
    pub(crate) fn from_array(len: usize, bytes: [u8; MAX_PAYLOAD]) -> Option<Payload> {
        Some(Payload {
            len: u16::try_from(len)
                .ok()
                .filter(|l| usize::from(*l) <= MAX_PAYLOAD)?,
            bytes,
        })
    }
}

/// What a single-use token is for. A token redeems only for the purpose
/// it was issued for.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// Confirming an email address.
    VerifyEmail,
    /// Setting a new password.
    ResetPassword,
    /// Signing in from a link.
    SignInLink,
    /// Seeing a draft at its real path.
    Preview,
    /// An application-defined purpose.
    Custom(u16),
}

impl Purpose {
    /// The payload a single-use token stores: a marker and the purpose.
    pub(crate) fn payload(self) -> [u8; 4] {
        let (kind, code) = match self {
            Purpose::VerifyEmail => (1, 0),
            Purpose::ResetPassword => (2, 0),
            Purpose::SignInLink => (3, 0),
            Purpose::Preview => (4, 0),
            Purpose::Custom(code) => (5, code),
        };
        let [a, b] = code.to_le_bytes();
        [b'S', kind, a, b]
    }
}

/// A valid session, as [`Validation::Valid`] returns it. A `Copy` value of
/// fixed size, the payload inline: validating allocates nothing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Session {
    pub(crate) account: AccountId,
    pub(crate) created_ms: u64,
    pub(crate) expires_ms: u64,
    /// The account's epoch when the session was issued. Signing the account
    /// out everywhere raises the epoch, which ends every older session.
    pub(crate) epoch: u32,
    /// Idle limit in milliseconds; 0 for none.
    pub(crate) idle_ms: u64,
    /// When the application should check the account again, in ms; 0 for
    /// never.
    pub(crate) recheck_ms: u64,
    pub(crate) payload: Payload,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("account", &self.account)
            .field("created_ms", &self.created_ms)
            .field("expires_ms", &self.expires_ms)
            .field("payload_len", &self.payload.len)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// The account the session belongs to.
    #[must_use]
    pub const fn account(&self) -> AccountId {
        self.account
    }

    /// When the session was issued.
    #[must_use]
    pub fn created_at(&self) -> SystemTime {
        time_of(self.created_ms)
    }

    /// When the session stops being valid.
    #[must_use]
    pub fn expires_at(&self) -> SystemTime {
        time_of(self.expires_ms)
    }

    /// The idle limit, if the session has one.
    #[must_use]
    pub fn idle_limit(&self) -> Option<Duration> {
        (self.idle_ms != 0).then(|| Duration::from_millis(self.idle_ms))
    }

    /// When the application should check the account again, if it asked.
    #[must_use]
    pub fn recheck_at(&self) -> Option<SystemTime> {
        (self.recheck_ms != 0).then(|| time_of(self.recheck_ms))
    }

    /// The bytes stored with the session.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.payload.as_bytes()
    }
}

/// Why a session was revoked.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeReason {
    /// Revoked with [`revoke`](crate::Auth::revoke) (a sign-out, or an
    /// administrator).
    Revoked,
    /// Replaced by a new token with [`rotate`](crate::Auth::rotate).
    Rotated,
    /// Ended by [`revoke_all`](crate::Auth::revoke_all): the account was
    /// signed out everywhere.
    SignedOutEverywhere,
}

/// The outcome of validating a token. Every outcome except `Valid` means the
/// caller is not signed in.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// `Valid` carries the session by value, payload inline, so validating
// allocates nothing; boxing it would allocate on every request.
#[allow(clippy::large_enum_variant)]
pub enum Validation {
    /// The token names a live session.
    Valid(Session),
    /// The session's lifetime has passed.
    Expired,
    /// The session was revoked. A revoked session never validates again.
    Revoked {
        /// Why it was revoked.
        reason: RevokeReason,
    },
    /// The token is well formed but names no session.
    Unknown,
    /// The text is not a token (wrong length, alphabet, or version).
    Malformed,
}

impl Validation {
    /// The session, when valid.
    #[must_use]
    pub const fn session(&self) -> Option<Session> {
        match self {
            Validation::Valid(session) => Some(*session),
            _ => None,
        }
    }
}

/// The outcome of [`sign_in`](crate::Auth::sign_in).
///
/// A wrong password and an unknown identifier both give `Failed`, after the
/// same amount of work, so the outcome does not reveal which accounts exist.
#[non_exhaustive]
#[derive(Debug)]
pub enum SignIn {
    /// The password matched; a new session was issued.
    Success {
        /// The account signed in.
        account: AccountId,
        /// The new session's token, returned once.
        token: Token,
    },
    /// The identifier or the password is wrong.
    Failed,
    /// The password matched, but the account may not sign in: it is locked
    /// out after repeated failures, suspended, or banned. `until` is when it
    /// may sign in again; `None` means not without an administrator.
    ///
    /// Only returned after the password matched: a wrong password on such
    /// an account gives [`Failed`](SignIn::Failed), so only someone who knows
    /// the password learns the account is locked.
    LockedOut {
        /// When the account may sign in again, if ever.
        until: Option<SystemTime>,
    },
}

/// The outcome of [`verify_password`](crate::Auth::verify_password): a
/// sign-in without a new session.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Login {
    /// The password matched and the account may sign in.
    Verified(AccountId),
    /// The identifier or the password is wrong.
    Failed,
    /// As [`SignIn::LockedOut`].
    LockedOut {
        /// When the account may sign in again, if ever.
        until: Option<SystemTime>,
    },
}

/// Whether an account may sign in.
///
/// A lock-out or suspension whose `until` has passed reads as `Active`.
/// Setting a standing that takes access away (`LockedOut`, `Suspended`,
/// `Banned`) ends every session of the account in the same commit.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// May sign in.
    Active,
    /// May sign in; the application has not verified the account yet.
    PendingVerification,
    /// Locked after repeated failed sign-ins, until a time.
    LockedOut {
        /// When the lock ends.
        until: SystemTime,
    },
    /// Suspended by an administrator, until a time or until lifted.
    Suspended {
        /// When the suspension ends; `None` until lifted.
        until: Option<SystemTime>,
        /// An application-defined reason code.
        reason: u32,
    },
    /// Banned: may not sign in until an administrator sets another standing.
    Banned {
        /// An application-defined reason code.
        reason: u32,
    },
}

impl Standing {
    /// When the account may sign in again, or `None` when it may now
    /// (`Some(None)`: not without an administrator).
    pub(crate) fn blocked_until(&self, now_ms: u64) -> Option<Option<SystemTime>> {
        let passed = |t: SystemTime| ms_of(t) <= now_ms;
        match *self {
            Standing::Active | Standing::PendingVerification => None,
            Standing::LockedOut { until } if passed(until) => None,
            Standing::LockedOut { until } => Some(Some(until)),
            Standing::Suspended {
                until: Some(until), ..
            } if passed(until) => None,
            Standing::Suspended { until, .. } => Some(until),
            Standing::Banned { .. } => Some(None),
        }
    }

    /// The standing as a reader sees it at `now_ms`: a lock or suspension
    /// that has run out reads as `Active`.
    pub(crate) fn at(self, now_ms: u64) -> Standing {
        match self {
            Standing::LockedOut { .. } | Standing::Suspended { .. }
                if self.blocked_until(now_ms).is_none() =>
            {
                Standing::Active
            }
            other => other,
        }
    }
}

/// Milliseconds since the Unix epoch, 0 before it.
pub(crate) fn ms_of(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

pub(crate) use crate::core::time_of;

/// A password hashed with Argon2id by [`hash_password`](crate::Auth::hash_password).
///
/// Opaque: the hash cannot be read back, and `Debug` shows nothing of it. It
/// is wiped from memory when dropped. Hash before calling
/// [`commit`](crate::Database::commit), because hashing takes tens of
/// milliseconds by design and a commit closure may run more than once.
pub struct HashedPassword(pub(crate) String);

impl fmt::Debug for HashedPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HashedPassword(..)")
    }
}

impl Drop for HashedPassword {
    fn drop(&mut self) {
        let mut bytes = std::mem::take(&mut self.0).into_bytes();
        crypt_io::wipe_vec(&mut bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_spec_new_too_long_is_invalid() {
        assert!(SessionSpec::new(MAX_TTL + Duration::from_secs(1)).is_err());
        assert!(SessionSpec::new(MAX_TTL).is_ok());
    }

    #[test]
    fn test_validation_session_only_when_valid() {
        let session = Session {
            account: AccountId::from_bytes([1; 16]),
            created_ms: 1,
            expires_ms: 2,
            epoch: 0,
            idle_ms: 0,
            recheck_ms: 0,
            payload: Payload::EMPTY,
        };
        assert_eq!(Validation::Valid(session).session(), Some(session));
        assert_eq!(Validation::Unknown.session(), None);
        assert_eq!(session.expires_at(), UNIX_EPOCH + Duration::from_millis(2));
    }

    #[test]
    fn test_hashed_password_debug_hides_hash() {
        let h = HashedPassword("$argon2id$secret".to_owned());
        assert_eq!(format!("{h:?}"), "HashedPassword(..)");
    }
}
