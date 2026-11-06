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

/// How a new session behaves.
///
/// ```
/// use std::time::Duration;
/// use nex_db::SessionSpec;
///
/// let web = SessionSpec::web();
/// assert_eq!(web.ttl(), Duration::from_secs(30 * 24 * 60 * 60));
/// let short = SessionSpec::new(Duration::from_secs(3600))?;
/// assert_eq!(short.ttl(), Duration::from_secs(3600));
/// assert!(SessionSpec::new(Duration::ZERO).is_err());
/// # Ok::<(), nex_db::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionSpec {
    ttl: Duration,
}

impl SessionSpec {
    /// A browser session: valid for 30 days from issue.
    #[must_use]
    pub const fn web() -> Self {
        SessionSpec {
            ttl: Duration::from_secs(30 * 24 * 60 * 60),
        }
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
        Ok(SessionSpec { ttl })
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

/// A valid session, as [`Validation::Valid`] returns it. A small `Copy`
/// value: validating allocates nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    pub(crate) account: AccountId,
    pub(crate) created_ms: u64,
    pub(crate) expires_ms: u64,
    /// The account's epoch when the session was issued. Signing the account
    /// out everywhere raises the epoch, which ends every older session.
    pub(crate) epoch: u32,
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
        UNIX_EPOCH + Duration::from_millis(self.created_ms)
    }

    /// When the session stops being valid.
    #[must_use]
    pub fn expires_at(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(self.expires_ms)
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
}

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
