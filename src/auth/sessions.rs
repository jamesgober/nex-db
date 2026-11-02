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

    /// Number of slots, tombstones included.
    pub(crate) fn len(&self) -> usize {
        self.slots
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::AccountId;

    fn session() -> Session {
        Session {
            account: AccountId::from_bytes([7; 16]),
            created_ms: 1,
            expires_ms: 10,
        }
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
