//! The route index, behind the route-index seam.
//!
//! This version keeps routes in standard `HashMap`s (site, then path) behind
//! an `RwLock`. Each path keeps the versions of its route that running
//! snapshots may still read: a route set or removed at seq `s` is seen by
//! snapshots at `s` and later. The snapshot index with a perfect hash, a
//! radix trie, and lock-free reads replaces it behind the same calls.

use std::{
    collections::HashMap,
    sync::{PoisonError, RwLock},
};

use super::entity::RouteEntry;
use crate::core::record::Seq;

/// Versions of one path's route, oldest first: from each seq, the route
/// (or none, after a removal).
type Versions = Vec<(Seq, Option<RouteEntry>)>;

/// A site's routes by path.
type Paths = HashMap<String, Versions>;

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

    /// The route at `path` on `site` as a snapshot at `at` sees it.
    pub(crate) fn get_at(&self, site: &str, path: &str, at: Seq) -> Option<RouteEntry> {
        let sites = self.sites.read().unwrap_or_else(PoisonError::into_inner);
        sites
            .get(site)
            .and_then(|paths| paths.get(path))
            .and_then(|versions| versions.iter().rev().find(|(since, _)| *since <= at))
            .and_then(|(_, entry)| *entry)
    }

    /// Set (or, with `None`, remove) the route at `path` on `site` from
    /// `since` on.
    pub(crate) fn set(&self, site: &str, path: &str, since: Seq, entry: Option<RouteEntry>) {
        let mut sites = self.sites.write().unwrap_or_else(PoisonError::into_inner);
        let paths = sites.entry(site.to_owned()).or_default();
        let versions = paths.entry(path.to_owned()).or_default();
        // A version at the same seq (one commit setting a path twice) is
        // replaced.
        versions.retain(|(s, _)| *s != since);
        versions.push((since, entry));
        versions.sort_by_key(|(s, _)| *s);
    }

    /// Drop versions no snapshot at or after `watermark` can read: for each
    /// path, those older than its newest version at or below the mark, and
    /// paths whose only version left is a removal.
    pub(crate) fn prune(&self, watermark: Seq) {
        let mut sites = self.sites.write().unwrap_or_else(PoisonError::into_inner);
        for paths in sites.values_mut() {
            paths.retain(|_, versions| {
                if let Some(keep) = versions.iter().rposition(|(s, _)| *s <= watermark) {
                    let _ = versions.drain(..keep);
                }
                !(versions.len() == 1 && versions[0].1.is_none() && versions[0].0 <= watermark)
            });
        }
        sites.retain(|_, paths| !paths.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        content::entity::{RouteKind, Visibility},
        ids::Rid,
    };

    fn entry(revision: u32) -> RouteEntry {
        RouteEntry {
            entity: Rid::from_bytes([1; 16]),
            revision,
            kind: RouteKind::Page,
            visibility: Visibility::Public,
            locale: crate::content::locale::Locale::EN,
            canary: false,
        }
    }

    #[test]
    fn test_set_then_get_finds_only_that_site_and_path() {
        let table = RouteTable::new();
        table.set("example.com", "/a", 4, Some(entry(1)));
        assert_eq!(table.get("example.com", "/a"), Some(entry(1)));
        assert_eq!(table.get_at("example.com", "/a", 3), None);
        assert_eq!(table.get_at("example.com", "/a", 4), Some(entry(1)));
        assert_eq!(table.get("example.com", "/b"), None);
        assert_eq!(table.get("other.com", "/a"), None);
    }

    #[test]
    fn test_snapshots_see_the_version_of_their_time_until_pruned() {
        let table = RouteTable::new();
        table.set("s", "/a", 2, Some(entry(1)));
        table.set("s", "/a", 5, Some(entry(2)));
        table.set("s", "/a", 8, None);
        assert_eq!(table.get_at("s", "/a", 4), Some(entry(1)));
        assert_eq!(table.get_at("s", "/a", 6), Some(entry(2)));
        assert_eq!(table.get("s", "/a"), None);
        table.prune(6);
        assert_eq!(table.get_at("s", "/a", 6), Some(entry(2)));
        assert_eq!(table.get_at("s", "/a", 2), None);
        table.prune(9);
        assert!(table.sites.read().unwrap().is_empty());
    }
}
