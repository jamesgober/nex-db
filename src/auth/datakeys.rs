//! Per-account data keys, in a file of fixed slots beside the account store.
//!
//! Each account gets a random key that seals its private records (the
//! account record with its password hash, its TOTP secret, its recovery
//! codes). The key never travels in the commit log: it is written to its
//! slot and synced while the commit that first uses it is staged, so the
//! log and the account store hold those records only as ciphertext under
//! it. Erasing the account overwrites its slot with zeros and syncs: every
//! copy of its records, in the log or a store file, can no longer be read.
//!
//! The file is a header and 96-byte slots:
//!
//! ```text
//! header   "NXDBKEYS" [8], format u16 (1), slot size u16 (96), [4] zero
//! slot     account [16], created ms u64, nonce [24], key [32], tag [16]
//! ```
//!
//! An all-zero slot is free. The key is sealed with XChaCha20-Poly1305
//! under the auth file key, with the account id as associated data, so a
//! slot copied to another account fails to open.

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
};

use crypt_io::{Crypt, Zeroizing};

use crate::{
    core::fs,
    error::{Error, Result},
    ids::AccountId,
};

const MAGIC: &[u8; 8] = b"NXDBKEYS";
const FORMAT: u16 = 1;
const HEADER: usize = 16;
const SLOT: usize = 96;
/// The sealed key in a slot: nonce, key, and tag.
const SEALED: usize = 72;
/// Unsealed keys kept in memory; the cache is emptied when it fills.
const CACHE: usize = 65_536;

/// The data key file of one realm.
pub(crate) struct DataKeys {
    path: PathBuf,
    file_key: Zeroizing<[u8; 32]>,
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for DataKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataKeys")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

struct Inner {
    file: File,
    /// Each account's slot and the time its key was made.
    slots: HashMap<AccountId, (u32, u64)>,
    /// Free slots, below `count`.
    free: Vec<u32>,
    /// Slots in the file.
    count: u32,
    cache: HashMap<AccountId, Zeroizing<[u8; 32]>>,
    /// Keys made by this process, and when, until a checkpoint finds their
    /// accounts (or drops the keys of commits that never landed).
    pending: HashMap<AccountId, u64>,
}

fn io(what: &'static str) -> impl Fn(std::io::Error) -> Error {
    move |e| Error::storage(what, e)
}

impl DataKeys {
    /// Open the file at `path`, creating it when there is none.
    pub(crate) fn open(path: &Path, file_key: Zeroizing<[u8; 32]>) -> Result<DataKeys> {
        let fresh = !path.exists();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(io("opening the data key file"))?;
        if fresh {
            let mut header = [0u8; HEADER];
            header[..8].copy_from_slice(MAGIC);
            header[8..10].copy_from_slice(&FORMAT.to_le_bytes());
            header[10..12].copy_from_slice(&(SLOT as u16).to_le_bytes());
            file.write_all(&header)
                .and_then(|()| file.sync_all())
                .map_err(io("writing the data key file"))?;
            if let Some(dir) = path.parent() {
                fs::sync_names(dir)?;
            }
        }
        let mut bytes = Vec::new();
        let _ = file
            .seek(SeekFrom::Start(0))
            .and_then(|_| file.read_to_end(&mut bytes))
            .map_err(io("reading the data key file"))?;
        let corrupt = || Error::corrupt("the data key file", 0);
        let header = bytes.get(..HEADER).ok_or_else(corrupt)?;
        if &header[..8] != MAGIC
            || header[8..10] != FORMAT.to_le_bytes()
            || header[10..12] != (SLOT as u16).to_le_bytes()
        {
            return Err(corrupt());
        }
        // A slot cut short by a crash while the file grew never held a key
        // a commit used: the sync came first.
        let body = &bytes[HEADER..];
        let count = u32::try_from(body.len() / SLOT).map_err(|_| corrupt())?;
        let mut slots = HashMap::new();
        let mut free = Vec::new();
        for (n, slot) in body.chunks_exact(SLOT).enumerate() {
            let n = n as u32;
            if slot.iter().all(|b| *b == 0) {
                free.push(n);
                continue;
            }
            let account = AccountId::from_bytes(slot[..16].try_into().map_err(|_| corrupt())?);
            let created = u64::from_le_bytes(slot[16..24].try_into().map_err(|_| corrupt())?);
            if slots.insert(account, (n, created)).is_some() {
                return Err(corrupt());
            }
        }
        free.reverse();
        Ok(DataKeys {
            path: path.to_path_buf(),
            file_key,
            inner: Mutex::new(Inner {
                file,
                slots,
                free,
                count,
                cache: HashMap::new(),
                pending: HashMap::new(),
            }),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The key of `account`, or `None` when it has none (an account from
    /// before 0.5, or one erased).
    pub(crate) fn get(&self, account: AccountId) -> Result<Option<Zeroizing<[u8; 32]>>> {
        let mut inner = self.lock();
        if let Some(key) = inner.cache.get(&account) {
            return Ok(Some(key.clone()));
        }
        let Some(&(n, _)) = inner.slots.get(&account) else {
            return Ok(None);
        };
        let mut slot = [0u8; SLOT];
        let at = (HEADER + n as usize * SLOT) as u64;
        inner
            .file
            .seek(SeekFrom::Start(at))
            .and_then(|_| inner.file.read_exact(&mut slot))
            .map_err(io("reading a data key"))?;
        let corrupt = || Error::corrupt("a data key", 0);
        if slot[..16] != account.as_bytes()[..] {
            return Err(corrupt());
        }
        let plain = Crypt::xchacha20_poly1305()
            .decrypt_with_aad(
                &self.file_key[..],
                &slot[24..24 + SEALED],
                account.as_bytes(),
            )
            .map(Zeroizing::new)
            .map_err(|_| corrupt())?;
        let key: [u8; 32] = plain[..].try_into().map_err(|_| corrupt())?;
        let key = Zeroizing::new(key);
        if inner.cache.len() >= CACHE {
            inner.cache.clear();
        }
        let _ = inner.cache.insert(account, key.clone());
        Ok(Some(key))
    }

    /// The key of `account`, made now (written and synced) when it has
    /// none.
    pub(crate) fn get_or_make(
        &self,
        account: AccountId,
        now_ms: u64,
    ) -> Result<Zeroizing<[u8; 32]>> {
        if let Some(key) = self.get(account)? {
            return Ok(key);
        }
        let key =
            crypt_io::generate_key().map_err(|e| Error::storage("drawing random bytes", e))?;
        let key: Zeroizing<[u8; 32]> = Zeroizing::new(
            key[..]
                .try_into()
                .map_err(|_| Error::invalid("data key", "not 32 bytes"))?,
        );
        let sealed = Crypt::xchacha20_poly1305()
            .encrypt_with_aad(&self.file_key[..], &key[..], account.as_bytes())
            .map_err(|e| Error::storage("sealing a data key", e))?;
        if sealed.len() != SEALED {
            return Err(Error::corrupt("a sealed data key", 0));
        }
        let mut slot = [0u8; SLOT];
        slot[..16].copy_from_slice(account.as_bytes());
        slot[16..24].copy_from_slice(&now_ms.to_le_bytes());
        slot[24..24 + SEALED].copy_from_slice(&sealed);
        let mut inner = self.lock();
        // Made meanwhile by another commit of the same account.
        if inner.slots.contains_key(&account) {
            drop(inner);
            return self
                .get(account)?
                .ok_or_else(|| Error::corrupt("a data key", 0));
        }
        let (n, grows) = match inner.free.pop() {
            Some(n) => (n, false),
            None => (inner.count, true),
        };
        let at = (HEADER + n as usize * SLOT) as u64;
        let written = inner
            .file
            .seek(SeekFrom::Start(at))
            .and_then(|_| inner.file.write_all(&slot))
            .and_then(|()| {
                if grows {
                    inner.file.sync_all()
                } else {
                    inner.file.sync_data()
                }
            });
        if let Err(e) = written {
            if !grows {
                inner.free.push(n);
            }
            return Err(Error::storage("writing a data key", e));
        }
        if grows {
            inner.count += 1;
        }
        let _ = inner.slots.insert(account, (n, now_ms));
        let _ = inner.pending.insert(account, now_ms);
        if inner.cache.len() >= CACHE {
            inner.cache.clear();
        }
        let _ = inner.cache.insert(account, key.clone());
        Ok(key)
    }

    /// Destroy the key of `account`: its slot is overwritten with zeros and
    /// synced. Nothing to do when it has none.
    pub(crate) fn destroy(&self, account: AccountId) -> Result<()> {
        let mut inner = self.lock();
        let _ = inner.cache.remove(&account);
        let Some(&(n, _)) = inner.slots.get(&account) else {
            return Ok(());
        };
        let at = (HEADER + n as usize * SLOT) as u64;
        inner
            .file
            .seek(SeekFrom::Start(at))
            .and_then(|_| inner.file.write_all(&[0u8; SLOT]))
            .and_then(|()| inner.file.sync_data())
            .map_err(io("destroying a data key"))?;
        let _ = inner.slots.remove(&account);
        inner.free.push(n);
        Ok(())
    }

    /// The accounts whose keys this process made before `before_ms`, no
    /// longer tracked: the caller drops the keys of those that do not
    /// exist (their creating commit never landed).
    pub(crate) fn settle(&self, before_ms: u64) -> Vec<AccountId> {
        let mut inner = self.lock();
        let old: Vec<AccountId> = inner
            .pending
            .iter()
            .filter(|(_, made)| **made < before_ms)
            .map(|(a, _)| *a)
            .collect();
        for account in &old {
            let _ = inner.pending.remove(account);
        }
        old
    }

    /// The file, for a backup.
    #[allow(dead_code)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keys_are_made_once_survive_a_reopen_and_are_destroyed() {
        let dir = std::env::temp_dir().join(format!(
            "nex-db-datakeys-{}-{}",
            std::process::id(),
            crate::core::now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("account-keys");
        let file_key = Zeroizing::new([3u8; 32]);
        let (a, b) = (
            AccountId::from_bytes([1; 16]),
            AccountId::from_bytes([2; 16]),
        );
        let key_a = {
            let keys = DataKeys::open(&path, file_key.clone()).unwrap();
            assert!(keys.get(a).unwrap().is_none());
            let key_a = keys.get_or_make(a, 5).unwrap();
            assert_eq!(*keys.get_or_make(a, 6).unwrap(), *key_a);
            let _ = keys.get_or_make(b, 7).unwrap();
            assert_eq!(keys.settle(6), [a]);
            assert!(keys.settle(6).is_empty());
            key_a
        };
        let keys = DataKeys::open(&path, file_key.clone()).unwrap();
        assert_eq!(*keys.get(a).unwrap().unwrap(), *key_a);
        keys.destroy(a).unwrap();
        assert!(keys.get(a).unwrap().is_none());
        drop(keys);
        let keys = DataKeys::open(&path, file_key).unwrap();
        assert!(keys.get(a).unwrap().is_none());
        assert!(keys.get(b).unwrap().is_some());
        // The freed slot is used again, and the file does not grow.
        let len = std::fs::metadata(&path).unwrap().len();
        let _ = keys.get_or_make(AccountId::from_bytes([9; 16]), 8).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), len);
        // Under another file key nothing opens.
        drop(keys);
        let keys = DataKeys::open(&path, Zeroizing::new([4u8; 32])).unwrap();
        assert!(keys.get(b).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
