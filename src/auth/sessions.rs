//! The session table, behind the hot-table seam.
//!
//! This version keeps sessions in a standard `HashMap` behind an `RwLock`,
//! keyed by the token digest. The fixed-slot hot table with lock-free reads
//! and expiry reclamation replaces it behind the same calls.
//!
//! The table is read-latest by design: a revocation is visible to every
//! reader at once, so no snapshot can revive a revoked session. It lives in
//! memory; a checkpoint saves it and the log after the checkpoint rebuilds
//! the rest at open.
//!
//! A payload is stored with only its own bytes and copied into the
//! fixed-size [`Session`] a read returns. Each live session keeps the time
//! it was last used, updated under the read lock.

use std::{
    collections::HashMap,
    sync::{
        PoisonError, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use super::types::{Payload, RevokeReason, Session};
use crate::ids::AccountId;

/// One entry as a reader sees it: a live session, or the tombstone a
/// revocation leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// The session is returned by value, payload inline, so a read allocates
// nothing; boxing it would allocate on every validation.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Slot {
    Live(Session),
    Revoked(RevokeReason),
}

/// A live session as stored.
#[derive(Debug)]
struct Stored {
    account: AccountId,
    created_ms: u64,
    expires_ms: u64,
    epoch: u32,
    idle_ms: u64,
    recheck_ms: u64,
    payload: Option<Box<[u8]>>,
    /// When the session was last validated.
    seen: AtomicU64,
}

impl Stored {
    fn new(session: &Session, seen: u64) -> Stored {
        let bytes = session.payload.as_bytes();
        Stored {
            account: session.account,
            created_ms: session.created_ms,
            expires_ms: session.expires_ms,
            epoch: session.epoch,
            idle_ms: session.idle_ms,
            recheck_ms: session.recheck_ms,
            payload: (!bytes.is_empty()).then(|| bytes.into()),
            seen: AtomicU64::new(seen),
        }
    }

    fn session(&self) -> Session {
        let payload = self
            .payload
            .as_deref()
            .and_then(|b| Payload::new(b).ok())
            .unwrap_or(Payload::EMPTY);
        Session {
            account: self.account,
            created_ms: self.created_ms,
            expires_ms: self.expires_ms,
            epoch: self.epoch,
            idle_ms: self.idle_ms,
            recheck_ms: self.recheck_ms,
            payload,
        }
    }
}

#[derive(Debug)]
enum Entry {
    Live(Stored),
    Revoked(RevokeReason),
}

/// Sessions by token digest.
#[derive(Debug, Default)]
pub(crate) struct SessionTable {
    slots: RwLock<HashMap<[u8; 32], Entry>>,
}

impl SessionTable {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The slot for `digest`, with when a live session was last used.
    /// Allocates nothing.
    pub(crate) fn get_seen(&self, digest: &[u8; 32]) -> Option<(Slot, u64)> {
        let slots = self.slots.read().unwrap_or_else(PoisonError::into_inner);
        slots.get(digest).map(|entry| match entry {
            Entry::Live(stored) => (
                Slot::Live(stored.session()),
                stored.seen.load(Ordering::Relaxed),
            ),
            Entry::Revoked(reason) => (Slot::Revoked(*reason), 0),
        })
    }

    /// The slot for `digest`. Allocates nothing.
    pub(crate) fn get(&self, digest: &[u8; 32]) -> Option<Slot> {
        self.get_seen(digest).map(|(slot, _)| slot)
    }

    /// Record that the session `digest` was used at `now_ms`.
    pub(crate) fn touch(&self, digest: &[u8; 32], now_ms: u64) {
        let slots = self.slots.read().unwrap_or_else(PoisonError::into_inner);
        if let Some(Entry::Live(stored)) = slots.get(digest) {
            let _ = stored.seen.fetch_max(now_ms, Ordering::Relaxed);
        }
    }

    /// Install a live session. A digest that is already revoked stays
    /// revoked.
    pub(crate) fn insert(&self, digest: [u8; 32], session: Session) {
        let mut slots = self.slots.write().unwrap_or_else(PoisonError::into_inner);
        let _ = slots
            .entry(digest)
            .or_insert_with(|| Entry::Live(Stored::new(&session, session.created_ms)));
    }

    /// Replace the session with a tombstone.
    pub(crate) fn revoke(&self, digest: [u8; 32], reason: RevokeReason) {
        let mut slots = self.slots.write().unwrap_or_else(PoisonError::into_inner);
        let _ = slots.insert(digest, Entry::Revoked(reason));
    }

    /// Live sessions of `account` that are still valid at `now_ms` under
    /// `epoch`. Walks the whole table: the hot table that replaces this map
    /// keeps a per-account index instead.
    pub(crate) fn live_for(&self, account: AccountId, epoch: u32, now_ms: u64) -> u32 {
        let slots = self.slots.read().unwrap_or_else(PoisonError::into_inner);
        let live = slots.values().filter(|entry| {
            matches!(entry, Entry::Live(s)
                if s.account == account && s.epoch == epoch && now_ms < s.expires_ms)
        });
        u32::try_from(live.count()).unwrap_or(u32::MAX)
    }

    /// Number of slots, tombstones included.
    pub(crate) fn len(&self) -> usize {
        self.slots
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Every slot except sessions that expired before `now_ms`, with when
    /// each live one was last used, for a checkpoint.
    pub(crate) fn snapshot(&self, now_ms: u64) -> Vec<([u8; 32], Slot, u64)> {
        let slots = self.slots.read().unwrap_or_else(PoisonError::into_inner);
        slots
            .iter()
            .filter(|(_, entry)| !matches!(entry, Entry::Live(s) if s.expires_ms <= now_ms))
            .map(|(digest, entry)| match entry {
                Entry::Live(stored) => (
                    *digest,
                    Slot::Live(stored.session()),
                    stored.seen.load(Ordering::Relaxed),
                ),
                Entry::Revoked(reason) => (*digest, Slot::Revoked(*reason), 0),
            })
            .collect()
    }

    /// Put a slot back as a checkpoint held it.
    pub(crate) fn restore(&self, digest: [u8; 32], slot: Slot, seen: u64) {
        let entry = match slot {
            Slot::Live(session) => Entry::Live(Stored::new(&session, seen)),
            Slot::Revoked(reason) => Entry::Revoked(reason),
        };
        let mut slots = self.slots.write().unwrap_or_else(PoisonError::into_inner);
        let _ = slots.insert(digest, entry);
    }
}

/// The current epoch of each account that was ever signed out everywhere.
/// An account not listed is at epoch 0. Read-latest, like the sessions.
#[derive(Debug, Default)]
pub(crate) struct EpochTable {
    epochs: RwLock<HashMap<AccountId, u32>>,
}

impl EpochTable {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The account's epoch. Allocates nothing.
    pub(crate) fn get(&self, account: AccountId) -> u32 {
        let epochs = self.epochs.read().unwrap_or_else(PoisonError::into_inner);
        epochs.get(&account).copied().unwrap_or(0)
    }

    /// Raise the account's epoch to `epoch`. An epoch never goes down, so a
    /// replayed or reordered raise is harmless.
    pub(crate) fn raise(&self, account: AccountId, epoch: u32) {
        let mut epochs = self.epochs.write().unwrap_or_else(PoisonError::into_inner);
        let current = epochs.entry(account).or_insert(0);
        *current = (*current).max(epoch);
    }

    /// Every account's epoch, for a checkpoint.
    pub(crate) fn snapshot(&self) -> Vec<(AccountId, u32)> {
        let epochs = self.epochs.read().unwrap_or_else(PoisonError::into_inner);
        epochs.iter().map(|(a, e)| (*a, *e)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        Session {
            account: AccountId::from_bytes([7; 16]),
            created_ms: 1,
            expires_ms: 10,
            epoch: 0,
            idle_ms: 0,
            recheck_ms: 0,
            payload: Payload::EMPTY,
        }
    }

    #[test]
    fn test_payload_and_last_use_round_trip() {
        let table = SessionTable::new();
        let with = Session {
            payload: Payload::new(b"role=editor").unwrap(),
            ..session()
        };
        table.insert([5; 32], with);
        assert_eq!(table.get(&[5; 32]), Some(Slot::Live(with)));
        table.touch(&[5; 32], 7);
        table.touch(&[5; 32], 4);
        assert_eq!(table.get_seen(&[5; 32]).map(|(_, seen)| seen), Some(7));
        let snapshot = table.snapshot(0);
        let other = SessionTable::new();
        for (digest, slot, seen) in snapshot {
            other.restore(digest, slot, seen);
        }
        assert_eq!(other.get_seen(&[5; 32]), Some((Slot::Live(with), 7)));
    }

    #[test]
    fn test_live_for_counts_only_current_unexpired_sessions() {
        let table = SessionTable::new();
        table.insert([1; 32], session());
        table.insert(
            [2; 32],
            Session {
                epoch: 1,
                ..session()
            },
        );
        table.insert([3; 32], session());
        table.revoke([3; 32], RevokeReason::Revoked);
        table.insert(
            [4; 32],
            Session {
                account: AccountId::from_bytes([8; 16]),
                ..session()
            },
        );
        let account = AccountId::from_bytes([7; 16]);
        assert_eq!(table.live_for(account, 0, 5), 1);
        assert_eq!(table.live_for(account, 1, 5), 1);
        assert_eq!(table.live_for(account, 0, 10), 0);
    }

    #[test]
    fn test_epoch_only_rises() {
        let epochs = EpochTable::new();
        let account = AccountId::from_bytes([7; 16]);
        assert_eq!(epochs.get(account), 0);
        epochs.raise(account, 2);
        epochs.raise(account, 1);
        assert_eq!(epochs.get(account), 2);
    }

    #[test]
    fn test_insert_then_get_returns_live() {
        let table = SessionTable::new();
        table.insert([1; 32], session());
        assert_eq!(table.get(&[1; 32]), Some(Slot::Live(session())));
        assert_eq!(table.get(&[2; 32]), None);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_revoke_then_insert_stays_revoked() {
        let table = SessionTable::new();
        table.insert([1; 32], session());
        table.revoke([1; 32], RevokeReason::Revoked);
        table.insert([1; 32], session());
        assert_eq!(
            table.get(&[1; 32]),
            Some(Slot::Revoked(RevokeReason::Revoked))
        );
    }
}
