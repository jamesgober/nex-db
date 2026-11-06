//! The session table, behind the hot-table seam.
//!
//! This version keeps sessions in a standard `HashMap` behind an `RwLock`,
//! keyed by the token digest. The fixed-slot hot table with lock-free reads,
//! expiry reclamation, and checkpoints replaces it in 0.3 behind the same
//! three calls: `get`, `insert`, `revoke`.
//!
//! The table is read-latest by design: a revocation is visible to every
//! reader at once, so no snapshot can revive a revoked session. It lives in
//! memory only and is rebuilt from the commit log when the database opens.

use std::{
    collections::HashMap,
    sync::{PoisonError, RwLock},
};

use super::types::{RevokeReason, Session};
use crate::ids::AccountId;

/// One entry: a live session, or the tombstone a revocation leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Slot {
    Live(Session),
    Revoked(RevokeReason),
}

/// Sessions by token digest.
#[derive(Debug, Default)]
pub(crate) struct SessionTable {
    slots: RwLock<HashMap<[u8; 32], Slot>>,
}

impl SessionTable {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The slot for `digest`. Allocates nothing.
    pub(crate) fn get(&self, digest: &[u8; 32]) -> Option<Slot> {
        let slots = self.slots.read().unwrap_or_else(PoisonError::into_inner);
        slots.get(digest).copied()
    }

    /// Install a live session. A digest that is already revoked stays
    /// revoked.
    pub(crate) fn insert(&self, digest: [u8; 32], session: Session) {
        let mut slots = self.slots.write().unwrap_or_else(PoisonError::into_inner);
        let _ = slots.entry(digest).or_insert(Slot::Live(session));
    }

    /// Replace the session with a tombstone.
    pub(crate) fn revoke(&self, digest: [u8; 32], reason: RevokeReason) {
        let mut slots = self.slots.write().unwrap_or_else(PoisonError::into_inner);
        let _ = slots.insert(digest, Slot::Revoked(reason));
    }

    /// Live sessions of `account` that are still valid at `now_ms` under
    /// `epoch`. Walks the whole table: the hot table that replaces this map
    /// keeps a per-account index instead.
    pub(crate) fn live_for(&self, account: AccountId, epoch: u32, now_ms: u64) -> u32 {
        let slots = self.slots.read().unwrap_or_else(PoisonError::into_inner);
        let live = slots.values().filter(|slot| {
            matches!(slot, Slot::Live(s)
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
        }
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
