//! Recovery codes: ten one-time codes an account keeps on paper.

use std::fmt;

use crypt_io::Zeroizing;

use crate::error::{Error, Result};

/// Codes made at a time.
pub(crate) const COUNT: usize = 10;
/// Symbols per code.
const LEN: usize = 10;
/// Crockford's base32, lower case: no i, l, o, or u.
const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
/// Format of the stored record.
const FORMAT: u8 = 1;

/// New recovery codes, as
/// [`new_recovery_codes`](crate::AuthTx::new_recovery_codes) returns them:
/// shown once, for the account holder to keep. Each works once, with
/// [`use_recovery_code`](crate::AuthTx::use_recovery_code). Nothing shows
/// in `Debug`, and the codes are wiped when this is dropped.
pub struct RecoveryCodes {
    pub(crate) codes: Vec<Zeroizing<String>>,
}

impl RecoveryCodes {
    /// The codes, each as `xxxxx-xxxxx`.
    pub fn codes(&self) -> impl Iterator<Item = &str> {
        self.codes.iter().map(|c| c.as_str())
    }
}

impl fmt::Debug for RecoveryCodes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryCodes")
            .field("count", &self.codes.len())
            .finish_non_exhaustive()
    }
}

/// One new code: its text and its normalized symbols.
pub(crate) fn generate() -> Result<(Zeroizing<String>, Zeroizing<[u8; LEN]>)> {
    let random = crypt_io::generate_key().map_err(|e| Error::storage("drawing random bytes", e))?;
    // 50 bits from the first 7 bytes.
    let mut bits = 0u64;
    for b in &random[..7] {
        bits = (bits << 8) | u64::from(*b);
    }
    let mut symbols = Zeroizing::new([0u8; LEN]);
    for (i, s) in symbols.iter_mut().enumerate() {
        *s = ALPHABET[((bits >> (5 * i)) & 31) as usize];
    }
    let mut text = Zeroizing::new(String::with_capacity(LEN + 1));
    for (i, s) in symbols.iter().enumerate() {
        if i == LEN / 2 {
            text.push('-');
        }
        text.push(char::from(*s));
    }
    Ok((text, symbols))
}

/// A code as typed, normalized: dashes and spaces dropped, upper case
/// lowered, and i, l, o read as 1, 1, 0. `None` when it is not a code.
pub(crate) fn normalize(code: &str) -> Option<Zeroizing<[u8; LEN]>> {
    let mut out = Zeroizing::new([0u8; LEN]);
    let mut n = 0;
    for c in code.bytes() {
        let c = match c.to_ascii_lowercase() {
            b'-' | b' ' => continue,
            b'i' | b'l' => b'1',
            b'o' => b'0',
            c => c,
        };
        if !ALPHABET.contains(&c) || n == LEN {
            return None;
        }
        out[n] = c;
        n += 1;
    }
    (n == LEN).then_some(out)
}

/// The stored digests of an account's codes.
pub(crate) fn encode(digests: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 32 * digests.len());
    out.push(FORMAT);
    out.push(digests.len() as u8);
    for d in digests {
        out.extend_from_slice(d);
    }
    out
}

pub(crate) fn decode(bytes: &[u8]) -> Result<Vec<[u8; 32]>> {
    let corrupt = || Error::corrupt("a recovery code record", 0);
    let [format, count, rest @ ..] = bytes else {
        return Err(corrupt());
    };
    if *format != FORMAT || rest.len() != 32 * usize::from(*count) {
        return Err(corrupt());
    }
    Ok(rest
        .chunks_exact(32)
        .map(|c| {
            let mut d = [0; 32];
            d.copy_from_slice(c);
            d
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codes_normalize_and_round_trip() {
        let (text, symbols) = generate().unwrap();
        assert_eq!(text.len(), 11);
        assert_eq!(normalize(&text).unwrap(), symbols);
        assert_eq!(normalize(&text.to_uppercase()).unwrap(), symbols);
        assert_eq!(normalize(" o1abc-defgh ").unwrap()[..2], *b"01");
        assert!(normalize("short").is_none());
        assert!(normalize("abcdefghjkm").is_none());
        assert!(normalize("abcde-fghju").is_none());
        let digests = [[1; 32], [2; 32]];
        assert_eq!(decode(&encode(&digests)).unwrap(), digests);
        assert!(decode(&[1, 2, 0]).is_err());
    }
}
