//! Session tokens.
//!
//! A token is 36 bytes: a version byte, a 3-byte routing prefix (region and
//! shard; zero in embedded mode, never trusted), and 32 random bytes from the
//! operating system's CSPRNG. Its text form is 48 characters of URL-safe
//! base64 without padding, ready for a cookie. The database keeps only a
//! keyed BLAKE3 digest of the random part, so a copy of the database files
//! does not hold usable tokens.

use std::fmt;

use crypt_io::Zeroizing;

use crate::error::{Error, Result};

/// The token format this version issues and accepts.
const VERSION: u8 = 1;

/// Binary token length.
const BINARY_LEN: usize = 36;

/// Text token length.
pub(crate) const TEXT_LEN: usize = 48;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// A session token. The plaintext exists once, in the value returned when
/// the session is issued; nex-db stores only its digest.
///
/// `Debug` shows nothing of the token, there is no `Display`, and the text is
/// wiped from memory when the value is dropped. Read it with
/// [`as_str`](Token::as_str) to set a cookie.
///
/// ```no_run
/// # fn main() -> nex_db::Result<()> {
/// # let db = nex_db::open("data/site")?;
/// # let account = nex_db::AccountId::from_bytes([1; 16]);
/// let token = db.auth().issue_session(account, nex_db::SessionSpec::web())?;
/// assert_eq!(format!("{token:?}"), "Token(..)");
/// let cookie_value: &str = token.as_str();
/// # let _ = cookie_value;
/// # Ok(())
/// # }
/// ```
pub struct Token(String);

impl Token {
    /// A new random token. Returns the token and its random part.
    pub(crate) fn generate() -> Result<(Token, Zeroizing<[u8; 32]>)> {
        let random =
            crypt_io::generate_key().map_err(|e| Error::storage("drawing random bytes", e))?;
        let mut binary = Zeroizing::new([0u8; BINARY_LEN]);
        binary[0] = VERSION;
        binary[4..].copy_from_slice(&random[..]);
        let mut text = String::with_capacity(TEXT_LEN);
        for chunk in binary.chunks_exact(3) {
            let n = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
            for shift in [18, 12, 6, 0] {
                text.push(char::from(ALPHABET[((n >> shift) & 63) as usize]));
            }
        }
        Ok((Token(text), random))
    }

    /// The token's text, for a cookie or a header.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A token the auth process issued, when `text` is a token this version
    /// issues.
    #[cfg(feature = "split-auth")]
    pub(crate) fn from_text(text: String) -> Option<Token> {
        let token = Token(text);
        parse(token.as_str()).map(|_| token)
    }
}

impl AsRef<str> for Token {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(..)")
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        let mut bytes = std::mem::take(&mut self.0).into_bytes();
        crypt_io::wipe_vec(&mut bytes);
    }
}

/// Each byte's 6-bit value in the alphabet; 0xFF for bytes outside it.
const DECODE: [u8; 256] = {
    let mut table = [0xFF; 256];
    let mut i = 0;
    while i < ALPHABET.len() {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
};

/// The random part of a token in text form, or `None` when the text is not a
/// token this version issues (wrong length, alphabet, or version).
/// Allocates nothing, and decodes straight into the one buffer it wipes.
pub(crate) fn parse(text: &str) -> Option<Zeroizing<[u8; 32]>> {
    let text = text.as_bytes();
    if text.len() != TEXT_LEN {
        return None;
    }
    // Any byte outside the alphabet sets the top bit of `bad`.
    let mut bad = 0u8;
    let mut quad = |q: &[u8]| {
        q.iter().fold(0u32, |n, &c| {
            let v = DECODE[usize::from(c)];
            bad |= v;
            (n << 6) | u32::from(v & 63)
        })
    };
    // The first quad is the version and the routing prefix's first two
    // bytes; the second, the prefix's last byte and two random bytes.
    let head = quad(&text[..4]);
    let next = quad(&text[4..8]);
    let mut random = Zeroizing::new([0u8; 32]);
    random[0] = (next >> 8) as u8;
    random[1] = next as u8;
    for (q, out) in text[8..]
        .chunks_exact(4)
        .zip(random[2..].chunks_exact_mut(3))
    {
        let n = quad(q);
        out[0] = (n >> 16) as u8;
        out[1] = (n >> 8) as u8;
        out[2] = n as u8;
    }
    if bad & 0x80 != 0 || (head >> 16) as u8 != VERSION {
        return None;
    }
    Some(random)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_parses_back_to_its_random_part() {
        let (token, random) = Token::generate().unwrap();
        assert_eq!(token.as_str().len(), TEXT_LEN);
        assert_eq!(*parse(token.as_str()).unwrap(), *random);
    }

    #[test]
    fn test_generate_twice_differs() {
        let (a, _) = Token::generate().unwrap();
        let (b, _) = Token::generate().unwrap();
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn test_parse_wrong_length_is_none() {
        assert!(parse("").is_none());
        assert!(parse(&"A".repeat(TEXT_LEN - 1)).is_none());
        assert!(parse(&"A".repeat(TEXT_LEN + 1)).is_none());
    }

    #[test]
    fn test_parse_bad_alphabet_is_none() {
        let (token, _) = Token::generate().unwrap();
        let mut text = token.as_str().to_owned();
        text.replace_range(10..11, "+");
        assert!(parse(&text).is_none());
    }

    #[test]
    fn test_parse_wrong_version_is_none() {
        // Version byte 0: the first four characters encode 0x00 0x00 0x00.
        let text = format!("AAAA{}", "A".repeat(TEXT_LEN - 4));
        assert!(parse(&text).is_none());
    }

    #[test]
    fn test_parse_bytes_outside_the_alphabet_are_none() {
        let (token, _) = Token::generate().unwrap();
        for bad in ["=", "\0", " ", "\u{7f}"] {
            let mut text = token.as_str().to_owned();
            text.replace_range(40..41, bad);
            assert!(parse(&text).is_none(), "{bad:?}");
        }
        // Two bytes of one character in place of two characters.
        let mut text = token.as_str().to_owned();
        text.replace_range(20..22, "\u{e9}");
        assert_eq!(text.len(), TEXT_LEN);
        assert!(parse(&text).is_none());
    }

    #[test]
    fn test_debug_hides_the_token() {
        let (token, _) = Token::generate().unwrap();
        assert_eq!(format!("{token:?}"), "Token(..)");
    }
}
