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

/// Routes by site, then by path.
#[derive(Debug, Default)]
pub(crate) struct RouteTable {
    sites: RwLock<HashMap<String, HashMap<String, RouteEntry>>>,
}

impl RouteTable {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The route at `path` on `site`. Allocates nothing.
    pub(crate) fn get(&self, site: &str, path: &str) -> Option<RouteEntry> {
        let sites = self.sites.read().unwrap_or_else(PoisonError::into_inner);
        sites.get(site).and_then(|paths| paths.get(path)).copied()
    }

    /// Set the route at `path` on `site`.
    pub(crate) fn insert(&self, site: &str, path: &str, entry: RouteEntry) {
        let mut sites = self.sites.write().unwrap_or_else(PoisonError::into_inner);
        let _ = sites
            .entry(site.to_owned())
            .or_default()
            .insert(path.to_owned(), entry);
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
        table.insert("example.com", "/a", entry);
        assert_eq!(table.get("example.com", "/a"), Some(entry));
        assert_eq!(table.get("example.com", "/b"), None);
        assert_eq!(table.get("other.com", "/a"), None);
    }
}
