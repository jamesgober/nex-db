//! The route index, behind the route-index seam.
//!
//! This version keeps routes in standard `HashMap`s (site, then path) behind
//! an `RwLock`. The snapshot index with a perfect hash, a radix trie, and
//! lock-free thread-cached reads replaces it in 0.4 behind the same two
//! calls: `get` and `insert`.

use std::{
    collections::HashMap,
    sync::{PoisonError, RwLock},
};

use super::entity::RouteEntry;
use crate::core::record::Seq;

/// A site's routes by path, each with the sequence number that created it
/// (0 for routes loaded from the store, which every snapshot sees).
type Paths = HashMap<String, (Seq, RouteEntry)>;

/// Routes by site, then by path.
#[derive(Debug, Default)]
pub(crate) struct RouteTable {
    sites: RwLock<HashMap<String, Paths>>,
}

impl RouteTable {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The route at `path` on `site`. Allocates nothing.
    pub(crate) fn get(&self, site: &str, path: &str) -> Option<RouteEntry> {
        self.get_at(site, path, Seq::MAX)
    }

    /// The route at `path` on `site` as a snapshot at `at` sees it. Routes
    /// are only ever added in this version, so a route is visible from the
    /// commit that created it on.
    pub(crate) fn get_at(&self, site: &str, path: &str, at: Seq) -> Option<RouteEntry> {
        let sites = self.sites.read().unwrap_or_else(PoisonError::into_inner);
        sites
            .get(site)
            .and_then(|paths| paths.get(path))
            .filter(|(since, _)| *since <= at)
            .map(|(_, entry)| *entry)
    }

    /// Set the route at `path` on `site`, created at `since`.
    pub(crate) fn insert(&self, site: &str, path: &str, since: Seq, entry: RouteEntry) {
        let mut sites = self.sites.write().unwrap_or_else(PoisonError::into_inner);
        let _ = sites
            .entry(site.to_owned())
            .or_default()
            .insert(path.to_owned(), (since, entry));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{content::entity::RouteKind, ids::Rid};

    #[test]
    fn test_insert_then_get_finds_only_that_site_and_path() {
        let table = RouteTable::new();
        let entry = RouteEntry {
            entity: Rid::from_bytes([1; 16]),
            revision: 1,
            kind: RouteKind::Page,
        };
        table.insert("example.com", "/a", 4, entry);
        assert_eq!(table.get("example.com", "/a"), Some(entry));
        assert_eq!(table.get_at("example.com", "/a", 3), None);
        assert_eq!(table.get_at("example.com", "/a", 4), Some(entry));
        assert_eq!(table.get("example.com", "/b"), None);
        assert_eq!(table.get("other.com", "/a"), None);
    }
}
