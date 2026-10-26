//! The database root key.
//!
//! A new database gets a 32-byte random root key in `auth/keys`, written once
//! (atomic replace, owner-only on Unix) with a BLAKE3 checksum. The auth
//! engine derives its keys from it with keyed BLAKE3 and a fixed label per
//! use. An existing database whose key file is missing or damaged stays
//! closed with [`Error::KeyUnavailable`]: a new key would make every stored
//! digest unreadable.
//!
//! This file stands in for the key hierarchy (key-vault, sealed auth
//! sections) that replaces it in 0.3.

use std::path::Path;

use crypt_io::Zeroizing;

use super::fs;
use crate::error::{Error, Result};

/// Key file name, inside `auth/`.
pub(crate) const KEY_FILE: &str = "keys";

/// Key file format version.
const FORMAT: u16 = 1;

/// Key file length: format, key, checksum.
const FILE_LEN: usize = 2 + 32 + 32;

/// The 32-byte root key, wiped when dropped.
pub(crate) struct RootKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for RootKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RootKey(..)")
    }
}

impl RootKey {
    /// Derive a 32-byte key for one use, named by `label`.
    #[cfg_attr(not(feature = "auth"), allow(dead_code))]
    pub(crate) fn derive(&self, label: &[u8]) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(crypt_io::mac::blake3_keyed(&self.0, label))
    }
}

/// Create the key file in `auth_dir` unless one is already there.
pub(crate) fn create_if_missing(auth_dir: &Path) -> Result<()> {
    let path = auth_dir.join(KEY_FILE);
    if fs::read_optional(&path)?.is_some() {
        return Ok(());
    }
    let key = crypt_io::generate_key().map_err(|e| Error::storage("drawing random bytes", e))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(FILE_LEN));
    bytes.extend_from_slice(&FORMAT.to_le_bytes());
    bytes.extend_from_slice(&key[..]);
    let sum = crypt_io::hash::blake3(&bytes);
    bytes.extend_from_slice(&sum);
    fs::write_atomic(&path, &bytes)
}

/// Load the root key from `auth_dir`.
#[cfg_attr(not(feature = "auth"), allow(dead_code))]
pub(crate) fn load(auth_dir: &Path) -> Result<RootKey> {
    let bytes = fs::read_optional(&auth_dir.join(KEY_FILE))
        .map_err(|_| Error::KeyUnavailable)?
        .ok_or(Error::KeyUnavailable)?;
    let bytes = Zeroizing::new(bytes);
    if bytes.len() != FILE_LEN || bytes[..2] != FORMAT.to_le_bytes() {
        return Err(Error::KeyUnavailable);
    }
    let (body, sum) = bytes.split_at(2 + 32);
    if crypt_io::hash::blake3(body)[..] != *sum {
        return Err(Error::KeyUnavailable);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&body[2..]);
    Ok(RootKey(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nex-db-keys-{}-{}",
            std::process::id(),
            id_forge::ulid::Ulid::new()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_create_then_load_returns_same_key() {
        let dir = temp_dir();
        create_if_missing(&dir).unwrap();
        let a = load(&dir).unwrap().derive(b"x");
        create_if_missing(&dir).unwrap();
        let b = load(&dir).unwrap().derive(b"x");
        assert_eq!(*a, *b);
        assert_ne!(*a, *load(&dir).unwrap().derive(b"y"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_load_missing_is_key_unavailable() {
        let dir = temp_dir();
        assert!(matches!(load(&dir), Err(Error::KeyUnavailable)));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_load_damaged_is_key_unavailable() {
        let dir = temp_dir();
        create_if_missing(&dir).unwrap();
        let path = dir.join(KEY_FILE);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[5] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(load(&dir), Err(Error::KeyUnavailable)));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_debug_hides_key() {
        let dir = temp_dir();
        create_if_missing(&dir).unwrap();
        assert_eq!(format!("{:?}", load(&dir).unwrap()), "RootKey(..)");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
