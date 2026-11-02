//! Conflict tables for snapshot isolation.
//!
//! Each engine keeps one: the sequence number of the latest commit that wrote
//! each recently written key. A transaction with snapshot `S` conflicts when
//! a key it writes has an entry above `S`. Entries at or below the oldest
//! live snapshot can no longer cause a conflict and are pruned once the table
//! passes its soft limit, so its size follows the write rate times the age of
//! the oldest open transaction, not the history.

use std::{
    collections::HashMap,
    sync::{Mutex, PoisonError},
};

use super::record::Seq;

/// Entries kept before a prune is attempted.
const PRUNE_AT: usize = 1024;

/// Latest commit sequence number per recently written key.
#[derive(Debug, Default)]
pub(crate) struct ConflictTable {
    latest: Mutex<HashMap<Vec<u8>, Seq>>,
}

impl ConflictTable {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// True when any of `keys` was written after `snapshot`.
    pub(crate) fn conflicts<'k>(
        &self,
        keys: impl IntoIterator<Item = &'k [u8]>,
        snapshot: Seq,
    ) -> bool {
        let latest = self.latest.lock().unwrap_or_else(PoisonError::into_inner);
        keys.into_iter()
            .any(|key| latest.get(key).is_some_and(|&seq| seq > snapshot))
    }

    /// Record that `keys` were written at `seq`.
    pub(crate) fn record<'k>(&self, keys: impl IntoIterator<Item = &'k [u8]>, seq: Seq) {
        let mut latest = self.latest.lock().unwrap_or_else(PoisonError::into_inner);
        for key in keys {
            let _previous = latest.insert(key.to_vec(), seq);
        }
    }

    /// Drop entries at or below `watermark` (the oldest live snapshot) once
    /// the table is past its soft limit.
    pub(crate) fn prune(&self, watermark: Seq) {
        let mut latest = self.latest.lock().unwrap_or_else(PoisonError::into_inner);
        if latest.len() >= PRUNE_AT {
            latest.retain(|_, seq| *seq > watermark);
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.latest
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conflicts_write_after_snapshot_conflicts() {
        let table = ConflictTable::new();
        table.record([&b"k"[..]], 5);
        assert!(table.conflicts([&b"k"[..]], 4));
        assert!(!table.conflicts([&b"k"[..]], 5));
        assert!(!table.conflicts([&b"other"[..]], 0));
    }

    #[test]
    fn test_prune_below_limit_keeps_everything() {
        let table = ConflictTable::new();
        table.record([&b"k"[..]], 1);
        table.prune(10);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_prune_past_limit_drops_old_entries_only() {
        let table = ConflictTable::new();
        for i in 0..PRUNE_AT as u64 {
            table.record([&i.to_le_bytes()[..]], i + 1);
        }
        table.prune(10);
        assert_eq!(table.len(), PRUNE_AT - 10);
        assert!(table.conflicts([&20u64.to_le_bytes()[..]], 10));
    }
}
