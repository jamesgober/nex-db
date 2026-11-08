//! The page tree: each entity's children, in order.
//!
//! Derived, like the listing index: rebuilt from the entity heads at open and
//! updated as commits apply. Children of one parent are a range of an ordered
//! set, so `children` never scans entities.

use std::{
    collections::{BTreeSet, HashMap},
    sync::{PoisonError, RwLock},
};

use super::entity::Head;
use crate::ids::Rid;

/// An order as a key that sorts like the signed number.
fn order_key(order: i64) -> u64 {
    (order as u64) ^ (1 << 63)
}

#[derive(Debug, Default)]
struct Inner {
    /// (parent, order, child).
    rows: BTreeSet<([u8; 16], u64, [u8; 16])>,
    /// Each child's row, to remove it when the child changes.
    placed: HashMap<Rid, ([u8; 16], u64)>,
}

/// Children by parent.
#[derive(Debug, Default)]
pub(crate) struct Tree {
    inner: RwLock<Inner>,
}

impl Tree {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Drop `rid` as a child.
    pub(crate) fn remove(&self, rid: Rid) {
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        if let Some((parent, order)) = inner.placed.remove(&rid) {
            let _ = inner.rows.remove(&(parent, order, *rid.as_bytes()));
        }
    }

    /// Place `head` under its parent, if it has one.
    pub(crate) fn update(&self, head: &Head) {
        self.remove(head.rid);
        let Some(parent) = head.parent else {
            return;
        };
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        let row = (*parent.as_bytes(), order_key(head.order));
        let _ = inner.rows.insert((row.0, row.1, *head.rid.as_bytes()));
        let _ = inner.placed.insert(head.rid, row);
    }

    /// The children of `parent`, lowest order first, ties by record id.
    pub(crate) fn children(&self, parent: Rid) -> Vec<Rid> {
        let inner = self.inner.read().unwrap_or_else(PoisonError::into_inner);
        let p = *parent.as_bytes();
        inner
            .rows
            .range((p, 0, [0; 16])..=(p, u64::MAX, [u8::MAX; 16]))
            .map(|(_, _, child)| Rid::from_bytes(*child))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::{entity::Entity, locale::Locale};

    fn head(n: u8, parent: Option<u8>, order: i64) -> Head {
        let mut entity = Entity::new("page").order(order);
        if let Some(p) = parent {
            entity = entity.parent(Rid::from_bytes([p; 16]));
        }
        entity
            .into_head(Rid::from_bytes([n; 16]), 0, Locale::EN)
            .unwrap()
    }

    #[test]
    fn test_children_follow_order_then_id_and_moves() {
        let tree = Tree::new();
        tree.update(&head(1, None, 0));
        tree.update(&head(2, Some(1), 5));
        tree.update(&head(3, Some(1), -5));
        tree.update(&head(4, Some(1), 5));
        let ids = |p: u8| {
            tree.children(Rid::from_bytes([p; 16]))
                .iter()
                .map(|r| r.as_bytes()[0])
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(1), [3, 2, 4]);
        tree.update(&head(3, Some(2), 0));
        assert_eq!(ids(1), [2, 4]);
        assert_eq!(ids(2), [3]);
        tree.remove(Rid::from_bytes([2; 16]));
        assert_eq!(ids(1), [4]);
        assert!(order_key(-1) < order_key(0) && order_key(0) < order_key(1));
    }
}
