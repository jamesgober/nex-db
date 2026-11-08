//! API keys: long-lived credentials for programs, with scopes.
//!
//! A key's text is shown once. The account store keeps, under the key's
//! keyed digest, a sealed record (account, id, scopes, times), and under its
//! id the digest, so a key can be revoked by id. A revoked key's record stays,
//! marked, so it answers `Revoked` rather than `Unknown`.

use std::{fmt, time::SystemTime};

use super::token::Token;
use crate::{
    core::codec::{Reader, Writer},
    error::{Error, Result},
    ids::AccountId,
};

/// Format of a stored key record.
const FORMAT: u8 = 1;
/// Most scopes one key has.
pub(crate) const MAX_SCOPES: usize = 32;
/// Longest scope, in bytes.
const MAX_SCOPE: usize = 64;

/// The id of an API key: for listing and revoking it. Its text form is 32
/// hex digits; it cannot be turned into the key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ApiKeyId(pub(crate) [u8; 16]);

impl fmt::Debug for ApiKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ApiKeyId({self})")
    }
}

impl fmt::Display for ApiKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl std::str::FromStr for ApiKeyId {
    type Err = Error;

    fn from_str(text: &str) -> Result<ApiKeyId> {
        let bad = || Error::invalid("api key id", "not 32 hex digits");
        if text.len() != 32 {
            return Err(bad());
        }
        let mut id = [0; 16];
        for (i, byte) in id.iter_mut().enumerate() {
            *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2).ok_or_else(bad)?, 16)
                .map_err(|_| bad())?;
        }
        Ok(ApiKeyId(id))
    }
}

/// A new API key, as [`create_api_key`](crate::AuthTx::create_api_key)
/// returns it. Its text is shown here only: hand it to the program that
/// will use it. Nothing shows in `Debug`, and the text is wiped when this is
/// dropped.
pub struct ApiKey {
    pub(crate) id: ApiKeyId,
    pub(crate) token: Token,
}

impl ApiKey {
    /// The key's id, to revoke it later.
    #[must_use]
    pub const fn id(&self) -> ApiKeyId {
        self.id
    }

    /// The key's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.token.as_str()
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKey")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// What [`validate_api_key`](crate::Auth::validate_api_key) found.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiKeyCheck {
    /// A live key: its account, id, and scopes.
    Valid {
        /// The account the key acts for.
        account: AccountId,
        /// The key's id.
        id: ApiKeyId,
        /// What the key may do, as given when it was made.
        scopes: Vec<String>,
    },
    /// The key's expiry has passed.
    Expired,
    /// The key was revoked.
    Revoked,
    /// No such key.
    Unknown,
    /// Not a key: wrong length, alphabet, or version.
    Malformed,
}

/// A stored key record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyRecord {
    pub(crate) account: AccountId,
    pub(crate) id: ApiKeyId,
    pub(crate) created_ms: u64,
    /// 0 for never.
    pub(crate) expires_ms: u64,
    /// 0 while live.
    pub(crate) revoked_ms: u64,
    pub(crate) scopes: Vec<String>,
}

impl KeyRecord {
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(64);
        let mut w = Writer::new(&mut out);
        w.u8(FORMAT);
        w.bytes(self.account.as_bytes());
        w.bytes(&self.id.0);
        w.u64(self.created_ms);
        w.u64(self.expires_ms);
        w.u64(self.revoked_ms);
        w.u8(self.scopes.len() as u8);
        for scope in &self.scopes {
            w.str16(scope)?;
        }
        Ok(out)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<KeyRecord> {
        let mut r = Reader::new(bytes, "an api key record", 0);
        if r.u8()? != FORMAT {
            return Err(Error::corrupt("an api key record format", 0));
        }
        let account = AccountId::from_bytes(r.fixed()?);
        let id = ApiKeyId(r.fixed()?);
        let created_ms = r.u64()?;
        let expires_ms = r.u64()?;
        let revoked_ms = r.u64()?;
        let mut scopes = Vec::new();
        for _ in 0..r.u8()? {
            scopes.push(r.str16()?.to_owned());
        }
        r.finish()?;
        Ok(KeyRecord {
            account,
            id,
            created_ms,
            expires_ms,
            revoked_ms,
            scopes,
        })
    }

    /// What a check of this record finds at `now`.
    pub(crate) fn check(&self, now: u64) -> ApiKeyCheck {
        if self.revoked_ms != 0 {
            ApiKeyCheck::Revoked
        } else if self.expires_ms != 0 && now >= self.expires_ms {
            ApiKeyCheck::Expired
        } else {
            ApiKeyCheck::Valid {
                account: self.account,
                id: self.id,
                scopes: self.scopes.clone(),
            }
        }
    }
}

/// Refuse more than 32 scopes, or one empty, longer than 64 bytes, or with
/// a space or control character.
pub(crate) fn check_scopes(scopes: &[&str]) -> Result<Vec<String>> {
    if scopes.len() > MAX_SCOPES {
        return Err(Error::invalid("scopes", "at most 32"));
    }
    let mut out: Vec<String> = Vec::with_capacity(scopes.len());
    for scope in scopes {
        if scope.is_empty()
            || scope.len() > MAX_SCOPE
            || scope.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(Error::invalid(
                "scope",
                "must be 1 to 64 bytes without spaces",
            ));
        }
        if !out.iter().any(|s| s == scope) {
            out.push((*scope).to_owned());
        }
    }
    Ok(out)
}

/// Milliseconds since 1970 of `at`; an error before then.
pub(crate) fn ms_since_epoch(at: SystemTime) -> Result<u64> {
    at.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .map_err(|_| Error::invalid("expiry", "before 1970"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_record_round_trips_and_checks() {
        let record = KeyRecord {
            account: AccountId::from_bytes([1; 16]),
            id: ApiKeyId([2; 16]),
            created_ms: 3,
            expires_ms: 100,
            revoked_ms: 0,
            scopes: vec!["posts:read".into(), "posts:write".into()],
        };
        assert_eq!(
            KeyRecord::decode(&record.encode().unwrap()).unwrap(),
            record
        );
        assert!(matches!(record.check(50), ApiKeyCheck::Valid { .. }));
        assert_eq!(record.check(100), ApiKeyCheck::Expired);
        let revoked = KeyRecord {
            revoked_ms: 9,
            ..record
        };
        assert_eq!(revoked.check(50), ApiKeyCheck::Revoked);
        assert!(check_scopes(&["a b"]).is_err());
        assert_eq!(check_scopes(&["a", "a"]).unwrap(), vec!["a".to_owned()]);
        let id = ApiKeyId([0xab; 16]);
        assert_eq!(id.to_string().parse::<ApiKeyId>().unwrap(), id);
    }
}
