//! The audit chain: every security write of a realm, hash-chained.
//!
//! Each auth operation a commit applies (an account created, a session
//! issued or revoked, a sign-out everywhere, a standing changed) adds one
//! record to `auth/audit.chain` through audit-trail, in the same `apply`
//! that installs the operation. Records are linked by a keyed BLAKE3 hash
//! (the key derived from the root key), so a record changed, removed, or
//! inserted breaks the chain for anyone who verifies it with the key.
//!
//! The chain is the history the log no longer holds once a checkpoint
//! truncates it. Its records come only from the log, deterministically: the
//! actor is the commit (`commit <seq>.<n>`, the n-th event of the commit) and
//! the time is the one the operation carries. So a replay appends the same
//! bytes again: at open the file is cut back to the length the last
//! checkpoint recorded, and replay re-appends everything after it.
//!
//! The file is synced by each checkpoint, before the checkpoint that records
//! its length is written.

use std::{
    cell::Cell,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
};

use audit_trail::{
    Action, Actor, Chain, Clock, Digest, Hasher, Outcome, Record, RecordId, Sink, SinkError,
    Target, Timestamp,
    codec::{self, FILE_HEADER_LEN},
};
use crypt_io::Zeroizing;

use crate::{
    core::{
        codec::{Reader, Writer},
        record::Seq,
    },
    error::{Error, Result},
};

/// The chain file, inside `auth/`.
pub(crate) const AUDIT_FILE: &str = "audit.chain";

/// Where a chain stood at a checkpoint: enough to resume it without reading
/// the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tail {
    /// The file's length.
    pub(crate) len: u64,
    pub(crate) next_id: u64,
    pub(crate) last_hash: [u8; 32],
    pub(crate) last_nanos: u64,
}

impl Tail {
    /// An empty chain: just the file header.
    const EMPTY: Tail = Tail {
        len: FILE_HEADER_LEN as u64,
        next_id: 0,
        last_hash: [0; 32],
        last_nanos: 0,
    };

    pub(crate) fn encode(&self, w: &mut Writer<'_>) {
        w.u64(self.len);
        w.u64(self.next_id);
        w.bytes(&self.last_hash);
        w.u64(self.last_nanos);
    }

    pub(crate) fn decode(r: &mut Reader<'_>) -> Result<Tail> {
        Ok(Tail {
            len: r.u64()?,
            next_id: r.u64()?,
            last_hash: r.fixed()?,
            last_nanos: r.u64()?,
        })
    }
}

/// Keyed BLAKE3 for the chain links.
struct KeyedHasher {
    key: Zeroizing<[u8; 32]>,
    input: Vec<u8>,
}

impl Hasher for KeyedHasher {
    fn reset(&mut self) {
        self.input.clear();
    }

    fn update(&mut self, bytes: &[u8]) {
        self.input.extend_from_slice(bytes);
    }

    fn finalize(&mut self, out: &mut Digest) {
        *out = Digest::from_bytes(crypt_io::mac::blake3_keyed(&self.key, &self.input));
    }
}

/// Appends encoded records to the chain file.
struct FileSink {
    file: File,
    len: u64,
    buf: Vec<u8>,
}

impl Sink for FileSink {
    fn write(&mut self, record: &Record<'_>) -> std::result::Result<(), SinkError> {
        self.buf.clear();
        codec::encode_record(record, &mut self.buf).map_err(|_| SinkError::Other)?;
        self.file.write_all(&self.buf).map_err(|_| SinkError::Io)?;
        self.len += self.buf.len() as u64;
        Ok(())
    }
}

/// The time of the record being appended, set before each append.
struct GivenClock(Cell<u64>);

impl Clock for GivenClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_nanos(self.0.get())
    }
}

/// One realm's audit chain.
pub(crate) struct AuditChain {
    path: PathBuf,
    chain: Mutex<Option<Chain<KeyedHasher, FileSink, GivenClock>>>,
}

impl std::fmt::Debug for AuditChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditChain")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl AuditChain {
    /// Open the chain in `auth_dir` at `tail` (from the last checkpoint, or
    /// an empty chain when there is none). Records written after that
    /// checkpoint are cut; replay writes them again.
    ///
    /// # Errors
    ///
    /// [`Error::Corrupt`] when the file is shorter than the checkpoint says
    /// or its header is wrong; [`Error::Storage`] when it cannot be opened.
    pub(crate) fn open(
        auth_dir: &Path,
        key: Zeroizing<[u8; 32]>,
        tail: Option<Tail>,
    ) -> Result<Self> {
        let path = auth_dir.join(AUDIT_FILE);
        let tail = tail.unwrap_or(Tail::EMPTY);
        let storage = |e| Error::storage("opening the audit chain", e);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(storage)?;
        let on_disk = file.metadata().map_err(storage)?.len();
        if on_disk == 0 && tail == Tail::EMPTY {
            let mut header = Vec::with_capacity(FILE_HEADER_LEN);
            codec::write_file_header(&mut header);
            file.write_all(&header).map_err(storage)?;
            file.sync_all().map_err(storage)?;
        } else {
            if on_disk < tail.len {
                return Err(Error::corrupt(
                    "the audit chain (shorter than its checkpoint)",
                    on_disk,
                ));
            }
            let mut header = [0u8; FILE_HEADER_LEN];
            std::io::Read::read_exact(&mut file, &mut header).map_err(storage)?;
            codec::verify_file_header(&header)
                .map_err(|_| Error::corrupt("the audit chain header", 0))?;
            file.set_len(tail.len).map_err(storage)?;
        }
        std::io::Seek::seek(&mut file, std::io::SeekFrom::End(0)).map_err(storage)?;
        let chain = Chain::resume(
            KeyedHasher {
                key,
                input: Vec::new(),
            },
            FileSink {
                file,
                len: tail.len,
                buf: Vec::new(),
            },
            GivenClock(Cell::new(0)),
            RecordId::from_u64(tail.next_id),
            Digest::from_bytes(tail.last_hash),
            Timestamp::from_nanos(tail.last_nanos),
        );
        Ok(AuditChain {
            path,
            chain: Mutex::new(Some(chain)),
        })
    }

    /// Append the `n`-th event of commit `seq`, at `at_ms` (moved forward
    /// when needed so times strictly increase).
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] when the file cannot be written.
    pub(crate) fn append(
        &self,
        seq: Seq,
        n: u32,
        at_ms: u64,
        action: &str,
        target: &str,
    ) -> Result<()> {
        let mut guard = self.chain.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(chain) = guard.as_mut() else {
            return Err(Error::storage(
                "appending to the audit chain",
                "the chain was closed",
            ));
        };
        let nanos = at_ms
            .saturating_mul(1_000_000)
            .max(chain.last_timestamp().as_nanos().saturating_add(1));
        chain.clock().0.set(nanos);
        let actor = format!("commit {seq}.{n}");
        let _ = chain
            .append(
                Actor::new(&actor),
                Action::new(action),
                Target::new(target),
                Outcome::Success,
            )
            .map_err(|e| Error::storage("appending to the audit chain", e))?;
        Ok(())
    }

    /// Sync the file and return where the chain stands, for a checkpoint.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] when the sync fails.
    pub(crate) fn sync(&self) -> Result<Tail> {
        let mut guard = self.chain.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(chain) = guard.as_mut() else {
            return Err(Error::storage(
                "syncing the audit chain",
                "the chain was closed",
            ));
        };
        let tail = Tail {
            len: chain.sink_mut().len,
            next_id: chain.next_id().as_u64(),
            last_hash: chain.last_hash().into_bytes(),
            last_nanos: chain.last_timestamp().as_nanos(),
        };
        chain
            .sink_mut()
            .file
            .sync_all()
            .map_err(|e| Error::storage("syncing the audit chain", e))?;
        Ok(tail)
    }
}

/// Verify every record of the chain file at `path` under `key`. Returns the
/// number of records.
///
/// # Errors
///
/// [`Error::Corrupt`] at the first record that does not verify.
#[cfg(test)]
pub(crate) fn verify_file(path: &Path, key: &[u8; 32]) -> Result<u64> {
    let bytes = std::fs::read(path).map_err(|e| Error::storage("reading the audit chain", e))?;
    codec::verify_file_header(&bytes).map_err(|_| Error::corrupt("the audit chain header", 0))?;
    let mut verifier = audit_trail::Verifier::new(KeyedHasher {
        key: Zeroizing::new(*key),
        input: Vec::new(),
    });
    let mut at = FILE_HEADER_LEN;
    let mut count = 0;
    while at < bytes.len() {
        let (record, used) = codec::decode_record(&bytes[at..])
            .map_err(|_| Error::corrupt("an audit record", at as u64))?;
        verifier
            .verify(&record.as_record())
            .map_err(|_| Error::corrupt("the audit chain", at as u64))?;
        at += used;
        count += 1;
    }
    Ok(count)
}
