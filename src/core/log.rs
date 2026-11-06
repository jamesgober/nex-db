//! The commit log: one wal-db log in `core/log/`.
//!
//! wal-db frames each record with a length and a CRC32C, cuts a torn tail
//! when it opens, and coalesces concurrent syncs. This module adds nothing to
//! the framing; it bounds record size, opens the log under wal-db's strict
//! policy, and turns wal-db errors into nex-db errors.
//!
//! Strict open cuts only an unfinished last record, which never returned
//! `Ok`. Damage with an intact record after it, a missing segment, or a record
//! above the size limit fails the open and leaves the log as it is.

use std::path::Path;

use wal_db::{OpenPolicy, SegmentedStore, Wal, WalConfig};

use crate::error::{Error, Result};

/// Segment file size: 16 MiB.
const SEGMENT_SIZE: u64 = 16 * 1024 * 1024;

/// Largest record the log accepts: 16 MiB. A larger commit is refused before
/// it is written, and recovery refuses a length prefix above it.
pub(crate) const MAX_RECORD: usize = 16 * 1024 * 1024;

/// The commit log.
#[derive(Debug)]
pub(crate) struct CommitLog {
    wal: Wal<SegmentedStore>,
}

impl CommitLog {
    /// Open (or create) the log in `dir`. A torn tail left by a crash is cut
    /// here, by wal-db; damage before the tail refuses the open.
    pub(crate) fn open(dir: &Path) -> Result<Self> {
        let config = WalConfig::new()
            .with_max_record_size(MAX_RECORD as u32)
            .with_open_policy(OpenPolicy::Strict);
        let wal = Wal::open_segmented_with(dir, SEGMENT_SIZE, config)?;
        Ok(CommitLog { wal })
    }

    /// True when the log holds no record.
    pub(crate) fn is_empty(&self) -> bool {
        self.wal.is_empty()
    }

    /// Append `record` to the log. It is in the operating system's cache
    /// when this returns, not yet on stable storage: call
    /// [`sync`](Self::sync) before treating it as committed.
    pub(crate) fn append(&self, record: &[u8]) -> Result<()> {
        let _lsn = self.wal.append(record)?;
        Ok(())
    }

    /// Make every record appended before this call durable. Concurrent calls
    /// share one sync.
    pub(crate) fn sync(&self) -> Result<()> {
        self.wal.sync()?;
        Ok(())
    }

    /// Drop every record below the first one whose sequence number is at
    /// least `seq`; that record and the ones after it stay. Does nothing when
    /// no record reaches `seq`, so the log is never emptied.
    pub(crate) fn truncate_below(&self, seq: u64) -> Result<()> {
        let mut keep = None;
        for entry in self.wal.iter()? {
            let record = entry.map_err(Error::from)?;
            // The sequence number follows the two-byte record format.
            let at = record
                .data()
                .get(2..10)
                .and_then(|b| <[u8; 8]>::try_from(b).ok())
                .map(u64::from_le_bytes)
                .ok_or(Error::corrupt("a log record", record.lsn().get()))?;
            if at >= seq {
                keep = Some(record.lsn());
                break;
            }
        }
        if let Some(lsn) = keep {
            let _ = self.wal.truncate_before(lsn)?;
        }
        Ok(())
    }

    /// Call `f` with each record in log order, with its log offset.
    pub(crate) fn replay(&self, mut f: impl FnMut(u64, &[u8]) -> Result<()>) -> Result<()> {
        for entry in self.wal.iter()? {
            let record = entry.map_err(Error::from)?;
            f(record.lsn().get(), record.data())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_then_reopen_replays_in_order() {
        let dir = std::env::temp_dir().join(format!(
            "nex-db-log-{}-{}",
            std::process::id(),
            id_forge::ulid::Ulid::new()
        ));
        let log = CommitLog::open(&dir).unwrap();
        assert!(log.is_empty());
        log.append(b"one").unwrap();
        log.append(b"two").unwrap();
        log.sync().unwrap();
        drop(log);

        let log = CommitLog::open(&dir).unwrap();
        let mut seen = Vec::new();
        log.replay(|_, bytes| {
            seen.push(bytes.to_vec());
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, vec![b"one".to_vec(), b"two".to_vec()]);
        drop(log);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
