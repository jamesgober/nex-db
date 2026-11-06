//! The database root key and where it comes from.
//!
//! The auth engine derives its keys from one 32-byte root key with keyed
//! BLAKE3 and a fixed label per use. The root key comes from a [`Keys`]
//! source: a key file in the database directory (the default), a key file
//! elsewhere, or an environment variable. Keeping the key outside the
//! directory means a copy of the directory alone opens nothing.
//!
//! The directory keeps a key check, `auth/key.check`: a keyed hash of the
//! root key, which reveals nothing about it. Opening with a different key
//! fails with [`Error::KeyUnavailable`] before anything is decrypted, rather
//! than as damage later. A missing or damaged key file of an existing
//! database also keeps it closed: a new key would make every stored digest
//! and sealed record unreadable.

use std::{
    fmt,
    path::{Path, PathBuf},
};

use crypt_io::Zeroizing;

use super::fs;
use crate::error::{Error, Result};

/// Key file name, inside `auth/`.
pub(crate) const KEY_FILE: &str = "keys";

/// Key check file name, inside `auth/`.
const CHECK_FILE: &str = "key.check";

/// Label of the key check.
const CHECK_LABEL: &[u8] = b"nex-db 2026 root key check";

/// Where a database's root key comes from. Give it to
/// [`Builder::keys`](crate::Builder::keys).
///
/// ```no_run
/// # fn main() -> nex_db::Result<()> {
/// let db = nex_db::Database::builder("data/site")
///     .keys(nex_db::Keys::file("/etc/site/nex-db.key"))
///     .open()?;
/// # let _ = db;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Keys(Source);

#[derive(Clone, PartialEq, Eq)]
enum Source {
    Directory,
    File(PathBuf),
    Env(String),
}

impl Keys {
    /// A key file inside the database directory, `auth/keys`, created with
    /// the database. The default.
    #[must_use]
    pub fn in_directory() -> Keys {
        Keys(Source::Directory)
    }

    /// A key file at `path`, outside the database directory. Created (owner
    /// read and write only on Unix) when a new database is created and the
    /// file does not exist yet; for an existing database it must be there.
    #[must_use]
    pub fn file(path: impl Into<PathBuf>) -> Keys {
        Keys(Source::File(path.into()))
    }

    /// The root key in the environment variable `var`, as 64 hexadecimal
    /// characters. Make one with any source of 32 random bytes; the variable
    /// must be set for a new database too.
    #[must_use]
    pub fn env(var: impl Into<String>) -> Keys {
        Keys(Source::Env(var.into()))
    }
}

impl Default for Keys {
    fn default() -> Self {
        Keys::in_directory()
    }
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Names where the key is, never the key.
        match &self.0 {
            Source::Directory => f.write_str("Keys::in_directory()"),
            Source::File(path) => write!(f, "Keys::file({})", path.display()),
            Source::Env(var) => write!(f, "Keys::env({var})"),
        }
    }
}

/// Get the root key from `keys` for the database whose auth directory is
/// `auth_dir`, creating it when the source allows and the database is new,
/// and check it against the directory's key check.
///
/// # Errors
///
/// [`Error::KeyUnavailable`] when the key cannot be read, is malformed, or
/// is not the key this database was created with.
pub(crate) fn root_key(keys: &Keys, auth_dir: &Path, new_database: bool) -> Result<RootKey> {
    let root = match &keys.0 {
        Source::Directory => {
            let path = auth_dir.join(KEY_FILE);
            if new_database {
                create_file_if_missing(&path)?;
            }
            load_file(&path)?
        }
        Source::File(path) => {
            if new_database {
                create_file_if_missing(path)?;
            }
            load_file(path)?
        }
        Source::Env(var) => from_env(var)?,
    };
    check(&root, auth_dir)?;
    Ok(root)
}

/// Compare `root` with the directory's key check, writing the check when
/// there is none (a new database, or one from 0.1 or 0.2).
fn check(root: &RootKey, auth_dir: &Path) -> Result<()> {
    let path = auth_dir.join(CHECK_FILE);
    let expected = root.derive(CHECK_LABEL);
    match fs::read_optional(&path)? {
        Some(stored) if stored[..] == expected[..] => Ok(()),
        Some(_) => Err(Error::KeyUnavailable),
        None => fs::write_atomic(&path, &expected[..]),
    }
}

/// The root key in the environment variable `var` (64 hexadecimal
/// characters).
fn from_env(var: &str) -> Result<RootKey> {
    let text = Zeroizing::new(std::env::var(var).map_err(|_| Error::KeyUnavailable)?);
    parse_hex(&text).ok_or(Error::KeyUnavailable)
}

/// A root key written as 64 hexadecimal characters (either case, spaces
/// around allowed).
fn parse_hex(text: &str) -> Option<RootKey> {
    let text = text.trim().as_bytes();
    if text.len() != 64 {
        return None;
    }
    let hex = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let mut key = Zeroizing::new([0u8; 32]);
    for (byte, pair) in key.iter_mut().zip(text.chunks_exact(2)) {
        *byte = (hex(pair[0])? << 4) | hex(pair[1])?;
    }
    Some(RootKey(key))
}

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
    pub(crate) fn derive(&self, label: &[u8]) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(crypt_io::mac::blake3_keyed(&self.0, label))
    }
}

/// Create the key file at `path` unless one is already there.
pub(crate) fn create_file_if_missing(path: &Path) -> Result<()> {
    if fs::read_optional(path)?.is_some() {
        return Ok(());
    }
    let key = crypt_io::generate_key().map_err(|e| Error::storage("drawing random bytes", e))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(FILE_LEN));
    bytes.extend_from_slice(&FORMAT.to_le_bytes());
    bytes.extend_from_slice(&key[..]);
    let sum = crypt_io::hash::blake3(&bytes);
    bytes.extend_from_slice(&sum);
    fs::write_atomic(path, &bytes)
}

/// Load the root key from the key file at `path`.
pub(crate) fn load_file(path: &Path) -> Result<RootKey> {
    let bytes = fs::read_optional(path)
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
        create_file_if_missing(&dir.join(KEY_FILE)).unwrap();
        let a = load_file(&dir.join(KEY_FILE)).unwrap().derive(b"x");
        create_file_if_missing(&dir.join(KEY_FILE)).unwrap();
        let b = load_file(&dir.join(KEY_FILE)).unwrap().derive(b"x");
        assert_eq!(*a, *b);
        assert_ne!(*a, *load_file(&dir.join(KEY_FILE)).unwrap().derive(b"y"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_load_missing_is_key_unavailable() {
        let dir = temp_dir();
        assert!(matches!(
            load_file(&dir.join(KEY_FILE)),
            Err(Error::KeyUnavailable)
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_load_damaged_is_key_unavailable() {
        let dir = temp_dir();
        create_file_if_missing(&dir.join(KEY_FILE)).unwrap();
        let path = dir.join(KEY_FILE);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[5] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(
            load_file(&dir.join(KEY_FILE)),
            Err(Error::KeyUnavailable)
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_root_key_from_another_source_is_key_unavailable() {
        let dir = temp_dir();
        let _ = root_key(&Keys::in_directory(), &dir, true).unwrap();
        let other = dir.join("other.key");
        assert!(matches!(
            root_key(&Keys::file(&other), &dir, true),
            Err(Error::KeyUnavailable)
        ));
        // The right key again opens.
        let _ = root_key(&Keys::in_directory(), &dir, false).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_env_key_unset_is_key_unavailable() {
        let dir = temp_dir();
        assert!(matches!(
            root_key(&Keys::env("NEX_DB_TEST_KEY_NEVER_SET_4f1c"), &dir, true),
            Err(Error::KeyUnavailable)
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_parse_hex_takes_64_hex_characters_only() {
        let key = parse_hex(&format!(" {} ", "aB".repeat(32))).unwrap();
        assert_eq!(*key.0, [0xab; 32]);
        assert!(parse_hex(&"a".repeat(63)).is_none());
        assert!(parse_hex(&"a".repeat(65)).is_none());
        assert!(parse_hex(&format!("{}g", "a".repeat(63))).is_none());
    }

    #[test]
    fn test_debug_hides_key() {
        let dir = temp_dir();
        create_file_if_missing(&dir.join(KEY_FILE)).unwrap();
        assert_eq!(
            format!("{:?}", load_file(&dir.join(KEY_FILE)).unwrap()),
            "RootKey(..)"
        );
        assert_eq!(format!("{:?}", Keys::env("V")), "Keys::env(V)");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
