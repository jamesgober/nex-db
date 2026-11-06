//! Versions kept for running snapshots.
//!
//! An engine's store holds only the latest state. A read at an older
//! snapshot (`db.read`) needs the value a key had then, so each engine keeps,
//! in memory, every version of each key written since the oldest running
//! snapshot, together with the value the key had before the first of them.
//! A read at snapshot `S` takes the newest version at or below `S` when the
//! key is tracked, and the store otherwise.
//!
//! Correctness rests on one rule: a key leaves the overlay only when its
//! newest version is at or below the watermark (the oldest running
//! snapshot), so for every running snapshot the store holds the version it
//! must see. Snapshots older than the age limit are left out of the
//! watermark and their reads fail, so a forgotten reader cannot hold memory.
//!
//! Cost: one store read per written key in `apply` (for the value before),
//! and memory for the keys written while a snapshot runs. Pruned after every
//! commit, so without running snapshots the overlay stays empty.

// A build with no engine feature keeps no versions outside the tests.
#![cfg_attr(not(any(feature = "auth", feature = "content")), allow(dead_code))]

use std::{
    collections::HashMap,
    sync::{Arc, PoisonError, RwLock},
};

use super::record::Seq;
use crate::error::Result;

/// One key's versions, oldest first. The first entry is the value before the
/// key was first written while tracked, at sequence number 0.
type Chain = Vec<(Seq, Option<Arc<[u8]>>)>;

/// Recent versions by key.
#[derive(Debug, Default)]
pub(crate) struct Versions {
    keys: RwLock<HashMap<Vec<u8>, Chain>>,
}

impl Versions {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record that `key` holds `value` from `seq` on (`None`: removed).
    /// `before` reads the value the store holds now; it is called only when
    /// the key is not tracked yet, and before the store is changed.
    pub(crate) fn record(
        &self,
        key: &[u8],
        seq: Seq,
        value: Option<&[u8]>,
        before: impl FnOnce() -> Result<Option<Vec<u8>>>,
    ) -> Result<()> {
        let mut keys = self.keys.write().unwrap_or_else(PoisonError::into_inner);
        if !keys.contains_key(key) {
            let old = before()?.map(Arc::from);
            let _ = keys.insert(key.to_vec(), vec![(0, old)]);
        }
        if let Some(chain) = keys.get_mut(key) {
            // A replayed record is already there.
            if chain.last().is_some_and(|(last, _)| *last >= seq) {
                return Ok(());
            }
            chain.push((seq, value.map(Arc::from)));
        }
        Ok(())
    }

    /// The value `key` had at snapshot `at`, when the key is tracked:
    /// `Some(None)` means it did not exist then. `None` means not tracked:
    /// read the store.
    pub(crate) fn at(&self, key: &[u8], at: Seq) -> Option<Option<Arc<[u8]>>> {
        let keys = self.keys.read().unwrap_or_else(PoisonError::into_inner);
        let chain = keys.get(key)?;
        chain
            .iter()
            .rev()
            .find(|(seq, _)| *seq <= at)
            .map(|(_, value)| value.clone())
    }

    /// Drop what no running snapshot can read: a key whose newest version is
    /// at or below `watermark` leaves; others keep the newest version at or
    /// below it and everything after.
    pub(crate) fn prune(&self, watermark: Seq) {
        let mut keys = self.keys.write().unwrap_or_else(PoisonError::into_inner);
        keys.retain(|_, chain| {
            if chain.last().is_some_and(|(seq, _)| *seq <= watermark) {
                return false;
            }
            let keep_from = chain
                .iter()
                .rposition(|(seq, _)| *seq <= watermark)
                .unwrap_or(0);
            let _ = chain.drain(..keep_from);
            true
        });
    }

    /// Keys tracked now.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.keys
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(v: &Option<Option<Arc<[u8]>>>) -> Option<Option<&[u8]>> {
        v.as_ref().map(|inner| inner.as_deref())
    }

    #[test]
    fn test_reads_at_each_snapshot_see_their_version() {
        let versions = Versions::new();
        versions
            .record(b"k", 5, Some(b"five"), || Ok(Some(b"old".to_vec())))
            .unwrap();
        versions
            .record(b"k", 8, None, || panic!("tracked already"))
            .unwrap();
        assert_eq!(bytes(&versions.at(b"k", 4)), Some(Some(&b"old"[..])));
        assert_eq!(bytes(&versions.at(b"k", 5)), Some(Some(&b"five"[..])));
        assert_eq!(bytes(&versions.at(b"k", 7)), Some(Some(&b"five"[..])));
        assert_eq!(bytes(&versions.at(b"k", 8)), Some(None));
        assert_eq!(versions.at(b"other", 8), None);
    }

    #[test]
    fn test_prune_keeps_what_the_watermark_can_read() {
        let versions = Versions::new();
        versions.record(b"a", 3, Some(b"a3"), || Ok(None)).unwrap();
        versions.record(b"b", 3, Some(b"b3"), || Ok(None)).unwrap();
        versions
            .record(b"b", 6, Some(b"b6"), || unreachable!())
            .unwrap();
        versions.prune(4);
        // `a` ends at 3: the store holds it for every snapshot from 4 on.
        assert_eq!(versions.at(b"a", 4), None);
        // `b` changes at 6: a snapshot at 4 still needs b3.
        assert_eq!(bytes(&versions.at(b"b", 4)), Some(Some(&b"b3"[..])));
        assert_eq!(bytes(&versions.at(b"b", 6)), Some(Some(&b"b6"[..])));
        versions.prune(6);
        assert_eq!(versions.len(), 0);
    }

    #[test]
    fn test_replayed_record_is_ignored() {
        let versions = Versions::new();
        versions.record(b"k", 5, Some(b"x"), || Ok(None)).unwrap();
        versions.record(b"k", 5, Some(b"y"), || Ok(None)).unwrap();
        assert_eq!(bytes(&versions.at(b"k", 5)), Some(Some(&b"x"[..])));
    }
}
