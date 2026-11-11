//! Published entries kept decoded, so a read of a page served before takes
//! no store read and no decode.
//!
//! The cache holds entries as the store holds them now (the latest state).
//! A reader uses it only for a key the snapshot overlay does not track, in
//! which case the store's latest state is the one its snapshot sees.
//!
//! Filling races with applies: a reader reads the store, an apply changes
//! the entity, the reader caches what it read. So an apply, after it writes
//! the store and before its commit becomes visible, removes each entity it
//! changed and raises its shard's generation under the shard's lock; a
//! reader caches what it read only if the generation it saw before reading
//! the store is still current.
//!
//! Cost: memory for up to `capacity` entities' entries; a read-locked map
//! lookup on every read; on every apply, one write-locked removal per
//! changed entity.

use std::{
    collections::HashMap,
    sync::{
        PoisonError, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use super::{entity::Entry, locale::Locale};
use crate::ids::EntityId;

const SHARDS: usize = 64;

/// One shard: entries by entity, each with the locale asked for; and a
/// generation, raised whenever an entity of the shard changes.
#[derive(Default)]
struct Shard {
    map: RwLock<HashMap<EntityId, Vec<(Locale, Entry)>>>,
    generation: AtomicU64,
}

/// Published entries by entity and the locale asked for.
pub(crate) struct EntryCache {
    shards: Box<[Shard]>,
    /// Entities per shard at most; 0 turns the cache off.
    per_shard: usize,
}

impl std::fmt::Debug for EntryCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntryCache")
            .field("per_shard", &self.per_shard)
            .finish_non_exhaustive()
    }
}

/// A shard's generation seen before a store read, for [`EntryCache::fill`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ticket(u64);

impl EntryCache {
    /// A cache of up to `capacity` entities (0: none).
    pub(crate) fn new(capacity: usize) -> Self {
        EntryCache {
            shards: (0..SHARDS).map(|_| Shard::default()).collect(),
            per_shard: capacity.div_ceil(SHARDS),
        }
    }

    fn shard(&self, rid: EntityId) -> &Shard {
        // Ids end in random bits.
        &self.shards[usize::from(rid.as_bytes()[15]) % SHARDS]
    }

    /// The cached entry of `rid` asked for in `asked`.
    pub(crate) fn get(&self, rid: EntityId, asked: Locale) -> Option<Entry> {
        if self.per_shard == 0 {
            return None;
        }
        self.shard(rid)
            .map
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&rid)?
            .iter()
            .find(|(l, _)| *l == asked)
            .map(|(_, e)| e.clone())
    }

    /// Take before reading the store for an entry to cache.
    pub(crate) fn ticket(&self, rid: EntityId) -> Ticket {
        Ticket(self.shard(rid).generation.load(Ordering::Acquire))
    }

    /// Cache `entry`, read after `ticket`, unless `rid`'s shard changed
    /// since.
    pub(crate) fn fill(&self, ticket: Ticket, rid: EntityId, asked: Locale, entry: &Entry) {
        if self.per_shard == 0 {
            return;
        }
        let shard = self.shard(rid);
        let mut map = shard.map.write().unwrap_or_else(PoisonError::into_inner);
        if shard.generation.load(Ordering::Acquire) != ticket.0 {
            return;
        }
        if map.len() >= self.per_shard && !map.contains_key(&rid) {
            // Any entity makes room: the cache keeps no use order, so a
            // read writes nothing.
            if let Some(key) = map.keys().next().copied() {
                let _ = map.remove(&key);
            }
        }
        let entries = map.entry(rid).or_default();
        if !entries.iter().any(|(l, _)| *l == asked) {
            entries.push((asked, entry.clone()));
        }
    }

    /// Forget `rid`: after an apply wrote its change to the store, before
    /// the commit becomes visible.
    pub(crate) fn forget(&self, rid: EntityId) {
        let shard = self.shard(rid);
        let mut map = shard.map.write().unwrap_or_else(PoisonError::into_inner);
        let _ = shard.generation.fetch_add(1, Ordering::AcqRel);
        let _ = map.remove(&rid);
    }

    /// Forget everything: a change to how every entry reads.
    pub(crate) fn clear(&self) {
        for shard in self.shards.iter() {
            let mut map = shard.map.write().unwrap_or_else(PoisonError::into_inner);
            let _ = shard.generation.fetch_add(1, Ordering::AcqRel);
            map.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::entity::Entity;

    fn entry(n: u8) -> (EntityId, Entry) {
        let rid = EntityId::from_bytes([n; 16]);
        let head = Entity::new("page")
            .field("n", i64::from(n))
            .into_head(rid, 1, Locale::EN)
            .unwrap();
        let entry = head.entry(Locale::EN, 1, head.base().draft.clone(), None);
        (rid, entry)
    }

    #[test]
    fn test_a_fill_after_a_change_is_refused() {
        let cache = EntryCache::new(64);
        let (rid, e) = entry(1);
        let ticket = cache.ticket(rid);
        cache.forget(rid);
        cache.fill(ticket, rid, Locale::EN, &e);
        assert!(cache.get(rid, Locale::EN).is_none());
        let ticket = cache.ticket(rid);
        cache.fill(ticket, rid, Locale::EN, &e);
        assert_eq!(cache.get(rid, Locale::EN), Some(e.clone()));
        assert!(cache.get(rid, Locale::new("fr").unwrap()).is_none());
        cache.forget(rid);
        assert!(cache.get(rid, Locale::EN).is_none());
        let ticket = cache.ticket(rid);
        cache.fill(ticket, rid, Locale::EN, &e);
        cache.clear();
        assert!(cache.get(rid, Locale::EN).is_none());
    }

    #[test]
    fn test_a_full_shard_makes_room_and_zero_is_off() {
        // One entity per shard; ids ending in the same byte share one.
        let cache = EntryCache::new(SHARDS);
        let (a, ea) = entry(1);
        let (b, eb) = entry(1 + SHARDS as u8);
        cache.fill(cache.ticket(a), a, Locale::EN, &ea);
        cache.fill(cache.ticket(b), b, Locale::EN, &eb);
        assert!(cache.get(a, Locale::EN).is_none());
        assert!(cache.get(b, Locale::EN).is_some());
        let off = EntryCache::new(0);
        off.fill(off.ticket(a), a, Locale::EN, &ea);
        assert!(off.get(a, Locale::EN).is_none());
    }
}
