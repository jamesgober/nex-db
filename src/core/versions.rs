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
//! commit, so without running snapshots the overlay stays empty, and a read
//! then takes no lock: it sees a count of zero and goes to the store.
//!
//! A reader reads the store first and asks the overlay second. An apply
//! records a key here before it writes the store, so a reader that saw the
//! store's new value finds the key tracked and takes its version instead;
//! asking first would leave a window where the key is not tracked yet but
//! the store already holds a value the snapshot must not see.

// A build with no engine feature keeps no versions outside the tests.
#![cfg_attr(not(any(feature = "auth", feature = "content")), allow(dead_code))]

use std::{
    collections::HashMap,
    sync::{
        Arc, PoisonError, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use super::record::Seq;
use crate::error::Result;

/// One key's versions, oldest first. The first entry is the value before the
/// key was first written while tracked, at sequence number 0.
type Chain = Vec<(Seq, Option<Arc<[u8]>>)>;

/// What [`Versions::lookup`] found.
#[derive(Debug)]
pub(crate) enum Lookup {
    /// Not tracked: read the store.
    Untracked,
    /// Tracked: the value at the snapshot (`None`: did not exist), and
    /// whether it is the key's newest version.
    Tracked {
        value: Option<Arc<[u8]>>,
        newest: bool,
    },
}

/// Recent versions by key.
#[derive(Debug, Default)]
pub(crate) struct Versions {
    keys: RwLock<HashMap<Vec<u8>, Chain>>,
    /// Keys tracked, set under the write lock: zero lets a reader skip the
    /// lock.
    tracked: AtomicUsize,
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
            match chain.last_mut() {
                // A later commit is recorded already (a replay).
                Some((last, _)) if *last > seq => return Ok(()),
                // A second write to the key in one commit: a snapshot at
                // `seq` sees the last one, as the store will.
                Some((last, held)) if *last == seq => *held = value.map(Arc::from),
                _ => chain.push((seq, value.map(Arc::from))),
            }
        }
        self.tracked.store(keys.len(), Ordering::Release);
        Ok(())
    }

    /// True when any key is tracked; false lets a caller skip building a
    /// key to ask with.
    pub(crate) fn tracks_any(&self) -> bool {
        self.tracked.load(Ordering::Acquire) != 0
    }

    /// What a snapshot at `at` sees of `key`: whether the key is tracked,
    /// and if so its value then and whether that is its newest version (so
    /// the store's latest state as well).
    pub(crate) fn lookup(&self, key: &[u8], at: Seq) -> Lookup {
        if self.tracked.load(Ordering::Acquire) == 0 {
            return Lookup::Untracked;
        }
        let keys = self.keys.read().unwrap_or_else(PoisonError::into_inner);
        let Some(chain) = keys.get(key) else {
            return Lookup::Untracked;
        };
        match chain.iter().rposition(|(seq, _)| *seq <= at) {
            Some(i) => Lookup::Tracked {
                value: chain[i].1.clone(),
                newest: i + 1 == chain.len(),
            },
            None => Lookup::Untracked,
        }
    }

    /// The value `key` had at snapshot `at`, when the key is tracked:
    /// `Some(None)` means it did not exist then. `None` means not tracked:
    /// read the store.
    pub(crate) fn at(&self, key: &[u8], at: Seq) -> Option<Option<Arc<[u8]>>> {
        if self.tracked.load(Ordering::Acquire) == 0 {
            return None;
        }
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
        self.tracked.store(keys.len(), Ordering::Release);
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
    fn test_a_second_write_in_one_commit_replaces_the_first() {
        let versions = Versions::new();
        versions.record(b"k", 5, Some(b"x"), || Ok(None)).unwrap();
        versions.record(b"k", 5, Some(b"y"), || Ok(None)).unwrap();
        assert_eq!(bytes(&versions.at(b"k", 5)), Some(Some(&b"y"[..])));
        assert_eq!(bytes(&versions.at(b"k", 4)), Some(None));
        assert!(matches!(
            versions.lookup(b"k", 5),
            Lookup::Tracked { newest: true, .. }
        ));
    }

    #[test]
    fn test_a_replayed_earlier_record_is_ignored() {
        let versions = Versions::new();
        versions.record(b"k", 7, Some(b"seven"), || Ok(None)).unwrap();
        versions.record(b"k", 5, Some(b"five"), || Ok(None)).unwrap();
        assert_eq!(bytes(&versions.at(b"k", 7)), Some(Some(&b"seven"[..])));
        assert_eq!(bytes(&versions.at(b"k", 6)), Some(None));
    }
}
