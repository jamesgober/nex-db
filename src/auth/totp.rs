//! TOTP second factors: RFC 6238 codes as authenticator
//! apps compute them (HMAC-SHA1, six digits, 30-second steps), through
//! crypt-io's `otp` module.
//!
//! The account store keeps one sealed record per account: the secret,
//! whether the account confirmed it, the last step a code was accepted for
//! (so a code works once), and a new secret awaiting confirmation while the
//! confirmed one stays in force.

#[cfg(feature = "mfa")]
use std::fmt;

use crypt_io::Zeroizing;

use crate::error::{Error, Result};

/// Secret length, in bytes (160 bits, as RFC 4226 recommends).
pub(crate) const SECRET_LEN: usize = 20;
/// Digits per code.
#[cfg(feature = "mfa")]
pub(crate) const DIGITS: u32 = 6;
/// Steps of clock drift accepted either way.
#[cfg(feature = "mfa")]
pub(crate) const WINDOW: u32 = 1;
/// Format of the stored record: 2 since 0.8 (a pending secret beside the
/// confirmed one); 1 still reads.
const FORMAT: u8 = 2;
/// The 0.4.1 to 0.7 format: no pending secret.
const FORMAT_1: u8 = 1;
/// Bytes of a format 1 record.
const LEN_1: usize = 2 + 8 + SECRET_LEN;

#[cfg(feature = "mfa")]
/// A new TOTP secret, as [`add_totp`](crate::AuthTx::add_totp) returns it:
/// show it once, as a QR code of [`uri`](Self::uri) or as
/// [`secret`](Self::secret) text, then have the user confirm a code
/// ([`confirm_totp`](crate::AuthTx::confirm_totp)). Nothing shows in
/// `Debug`, and the secret is wiped when this is dropped.
pub struct TotpEnrollment {
    pub(crate) secret: Zeroizing<[u8; SECRET_LEN]>,
}

#[cfg(feature = "mfa")]
impl TotpEnrollment {
    /// The secret in base32 (RFC 4648, no padding), for typing into an app.
    #[must_use]
    pub fn secret(&self) -> Zeroizing<String> {
        base32(&self.secret[..])
    }

    /// The `otpauth://` URI authenticator apps read from a QR code:
    /// `issuer` is the site's name, `label` the account's (an email
    /// address, a username).
    #[must_use]
    pub fn uri(&self, issuer: &str, label: &str) -> Zeroizing<String> {
        let secret = self.secret();
        Zeroizing::new(format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period=30",
            escape(issuer),
            escape(label),
            secret.as_str(),
            escape(issuer),
        ))
    }
}

#[cfg(feature = "mfa")]
impl fmt::Debug for TotpEnrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpEnrollment").finish_non_exhaustive()
    }
}

#[cfg(feature = "mfa")]
/// RFC 4648 base32 without padding.
fn base32(bytes: &[u8]) -> Zeroizing<String> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Zeroizing::new(String::with_capacity(bytes.len() * 8 / 5 + 1));
    let mut buffer = 0u32;
    let mut bits = 0;
    for b in bytes {
        buffer = (buffer << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

#[cfg(feature = "mfa")]
/// Percent-encode everything but unreserved characters (RFC 3986).
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'@') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A stored TOTP record.
#[cfg_attr(not(feature = "mfa"), allow(dead_code))]
pub(crate) struct TotpRecord {
    pub(crate) secret: Zeroizing<[u8; SECRET_LEN]>,
    pub(crate) confirmed: bool,
    /// The step of the last code accepted; 0 before the first.
    pub(crate) last_step: u64,
    /// A new secret from `add_totp` on an account with TOTP on: the
    /// confirmed `secret` stays in force until a code of this one confirms
    /// it (before 0.8 `add_totp` replaced it, turning the factor off).
    pub(crate) pending: Option<Zeroizing<[u8; SECRET_LEN]>>,
}

impl TotpRecord {
    #[cfg(feature = "mfa")]
    pub(crate) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(LEN_1 + 1 + SECRET_LEN));
        out.push(FORMAT);
        out.push(u8::from(self.confirmed));
        out.extend_from_slice(&self.last_step.to_le_bytes());
        out.extend_from_slice(&self.secret[..]);
        match &self.pending {
            Some(pending) => {
                out.push(1);
                out.extend_from_slice(&pending[..]);
            }
            None => out.push(0),
        }
        out
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<TotpRecord> {
        let corrupt = || Error::corrupt("a TOTP record", 0);
        let pending = match (bytes.first(), bytes.len(), bytes.get(LEN_1)) {
            (Some(&FORMAT_1), LEN_1, _) => None,
            (Some(&FORMAT), n, Some(0)) if n == LEN_1 + 1 => None,
            (Some(&FORMAT), n, Some(1)) if n == LEN_1 + 1 + SECRET_LEN => {
                let mut pending = Zeroizing::new([0; SECRET_LEN]);
                pending.copy_from_slice(&bytes[LEN_1 + 1..]);
                Some(pending)
            }
            _ => return Err(corrupt()),
        };
        let confirmed = match bytes[1] {
            0 => false,
            1 => true,
            _ => return Err(corrupt()),
        };
        let mut step = [0; 8];
        step.copy_from_slice(&bytes[2..10]);
        let mut secret = Zeroizing::new([0; SECRET_LEN]);
        secret.copy_from_slice(&bytes[10..LEN_1]);
        Ok(TotpRecord {
            secret,
            confirmed,
            last_step: u64::from_le_bytes(step),
            pending,
        })
    }

    #[cfg(feature = "mfa")]
    /// The step `code` matches at `unix_seconds`, if it is later than the
    /// last one accepted: a code works once.
    pub(crate) fn accept(&self, code: &str, unix_seconds: u64) -> Option<u64> {
        let step =
            crypt_io::otp::totp_check(&self.secret[..], code, unix_seconds, DIGITS, WINDOW).ok()?;
        (step > self.last_step).then_some(step)
    }

    #[cfg(feature = "mfa")]
    /// The step `code` matches for the pending secret at `unix_seconds`.
    pub(crate) fn accept_pending(&self, code: &str, unix_seconds: u64) -> Option<u64> {
        let pending = self.pending.as_ref()?;
        crypt_io::otp::totp_check(&pending[..], code, unix_seconds, DIGITS, WINDOW).ok()
    }
}

#[cfg(all(test, feature = "mfa"))]
mod tests {
    use super::*;

    #[test]
    fn test_base32_matches_rfc_4648_and_uri_escapes() {
        assert_eq!(base32(b"").as_str(), "");
        assert_eq!(base32(b"f").as_str(), "MY");
        assert_eq!(base32(b"foobar").as_str(), "MZXW6YTBOI");
        let enrollment = TotpEnrollment {
            secret: Zeroizing::new(*b"12345678901234567890"),
        };
        assert_eq!(
            enrollment.secret().as_str(),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
        let uri = enrollment.uri("My Site", "ann@example.com");
        assert!(uri.starts_with("otpauth://totp/My%20Site:ann@example.com?secret=GEZD"));
        assert!(!format!("{enrollment:?}").contains("GEZD"));
    }

    #[test]
    fn test_record_round_trips_and_codes_work_once() {
        let record = TotpRecord {
            secret: Zeroizing::new(*b"12345678901234567890"),
            confirmed: true,
            last_step: 0,
            pending: None,
        };
        let back = TotpRecord::decode(&record.encode()).unwrap();
        assert!(back.confirmed);
        // Format 1, as 0.4.1 to 0.7 wrote it, still reads.
        let mut old = record.encode()[..LEN_1].to_vec();
        old[0] = FORMAT_1;
        let old = TotpRecord::decode(&old).unwrap();
        assert!(old.confirmed && old.pending.is_none());
        assert_eq!(old.secret[..], record.secret[..]);
        // A pending secret round-trips; lengths and flags are checked.
        let with = TotpRecord {
            pending: Some(Zeroizing::new([9; SECRET_LEN])),
            ..TotpRecord::decode(&record.encode()).unwrap()
        };
        let bytes = with.encode();
        assert_eq!(
            TotpRecord::decode(&bytes).unwrap().pending.unwrap()[..],
            [9; SECRET_LEN]
        );
        assert!(TotpRecord::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut flag = bytes.to_vec();
        flag[LEN_1] = 2;
        assert!(TotpRecord::decode(&flag).is_err());
        // RFC 6238 appendix B, SHA-1, at 59 s: 94287082 (eight digits); the
        // six-digit code is its last six.
        let step = back.accept("287082", 59).unwrap();
        assert_eq!(step, 1);
        let used = TotpRecord {
            last_step: step,
            ..back
        };
        assert!(used.accept("287082", 59).is_none());
        assert!(used.accept("000000", 59).is_none());
    }
}
