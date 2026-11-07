//! The listing index: published entities by site and type, newest first.
//!
//! Derived, like the route index: rebuilt from the entity heads at open and
//! updated as commits apply. Two orders per site and type: by first
//! publication (`latest`) and by the last publish (`updated`). A page is a
//! range read of an ordered set, so a listing never scans entities.

use std::{
    collections::{BTreeSet, HashMap},
    fmt,
    sync::{PoisonError, RwLock},
};

use super::entity::Head;
use crate::{
    error::{Error, Result},
    ids::Rid,
};

/// The most entries one page holds.
pub(crate) const MAX_PAGE: usize = 1000;
/// Entries in a page when no limit is set.
const DEFAULT_PAGE: usize = 100;

const ORDER_LATEST: u8 = 1;
const ORDER_UPDATED: u8 = 2;

/// A listing to read with [`Content::list`](crate::Content::list).
///
/// ```
/// use nex_db::Listing;
/// let recent = Listing::latest("post").site("example.com").limit(10);
/// # let _ = recent;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct Listing {
    pub(crate) kind: String,
    pub(crate) site: String,
    pub(crate) order: u8,
    pub(crate) limit: usize,
}

impl Listing {
    /// Published entities of type `kind`, the most recently first published
    /// first, on the default site.
    pub fn latest(kind: impl Into<String>) -> Listing {
        Listing {
            kind: kind.into(),
            site: crate::DEFAULT_SITE.to_owned(),
            order: ORDER_LATEST,
            limit: DEFAULT_PAGE,
        }
    }

    /// Order by the last publish instead: an edit that is published moves
    /// the entity to the front.
    pub fn updated(mut self) -> Listing {
        self.order = ORDER_UPDATED;
        self
    }

    /// Entities of `site` (default [`DEFAULT_SITE`](crate::DEFAULT_SITE)).
    pub fn site(mut self, site: impl Into<String>) -> Listing {
        self.site = site.into();
        self
    }

    /// At most `n` entries per page (1 to 1,000; default 100).
    pub fn limit(mut self, n: usize) -> Listing {
        self.limit = n.clamp(1, MAX_PAGE);
        self
    }
}

/// Where a listing goes on: give it to
/// [`Content::next_page`](crate::Content::next_page). Its text form
/// (`to_string`, [`Cursor::parse`]) can travel in a URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    pub(crate) listing: Listing,
    /// The last entry of the page: its inverted time and id.
    pub(crate) after: (u64, [u8; 16]),
}

impl fmt::Display for Cursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{:x}.",
            self.listing.order, self.listing.limit, self.after.0
        )?;
        for b in self.after.1 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(".")?;
        for b in self.listing.site.as_bytes() {
            write!(f, "{b:02x}")?;
        }
        f.write_str(".")?;
        for b in self.listing.kind.as_bytes() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

impl Cursor {
    /// A cursor from its text form.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when `text` is not a cursor.
    pub fn parse(text: &str) -> Result<Cursor> {
        let bad = || Error::invalid("cursor", "not a cursor");
        let parts: Vec<&str> = text.split('.').collect();
        let [order, limit, inv, rid, site, kind] = parts.as_slice() else {
            return Err(bad());
        };
        let order: u8 = order.parse().map_err(|_| bad())?;
        if order != ORDER_LATEST && order != ORDER_UPDATED {
            return Err(bad());
        }
        let limit: usize = limit.parse().map_err(|_| bad())?;
        let inv = u64::from_str_radix(inv, 16).map_err(|_| bad())?;
        let rid: [u8; 16] = unhex(rid).and_then(|b| b.try_into().ok()).ok_or_else(bad)?;
        let site = String::from_utf8(unhex(site).ok_or_else(bad)?).map_err(|_| bad())?;
        let kind = String::from_utf8(unhex(kind).ok_or_else(bad)?).map_err(|_| bad())?;
        Ok(Cursor {
            listing: Listing {
                kind,
                site,
                order,
                limit: limit.clamp(1, MAX_PAGE),
            },
            after: (inv, rid),
        })
    }
}

/// One page of a listing.
#[derive(Debug, Clone)]
pub struct Page<T> {
    pub(crate) items: Vec<T>,
    pub(crate) next: Option<Cursor>,
}

impl<T> Page<T> {
    /// The entries of the page.
    #[must_use]
    pub fn items(&self) -> &[T] {
        &self.items
    }

    /// The entries, owned.
    #[must_use]
    pub fn into_items(self) -> Vec<T> {
        self.items
    }

    /// Where the listing goes on, or `None` on its last page.
    #[must_use]
    pub fn next(&self) -> Option<&Cursor> {
        self.next.as_ref()
    }
}

/// An entry's place in one order: (group, order, inverted time, id).
type Row = (u32, u8, u64, [u8; 16]);

#[derive(Debug, Default)]
struct Inner {
    rows: BTreeSet<Row>,
    /// The group number of each (site, type).
    groups: HashMap<(String, String), u32>,
    /// Each listed entity's rows, to remove them when it changes.
    placed: HashMap<Rid, [Row; 2]>,
}

/// Published entities by site and type.
#[derive(Debug, Default)]
pub(crate) struct ListIndex {
    inner: RwLock<Inner>,
}

impl ListIndex {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Place `head` as it now is: listed when published, not otherwise.
    pub(crate) fn update(&self, head: &Head) {
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(rows) = inner.placed.remove(&head.rid) {
            for row in rows {
                let _ = inner.rows.remove(&row);
            }
        }
        if !head.is_published() {
            return;
        }
        let next = inner.groups.len() as u32;
        let group = *inner
            .groups
            .entry((head.site.clone(), head.kind.clone()))
            .or_insert(next);
        let rid = *head.rid.as_bytes();
        let rows = [
            (group, ORDER_LATEST, u64::MAX - head.first_published_ms, rid),
            (
                group,
                ORDER_UPDATED,
                u64::MAX - head.last_published_ms(),
                rid,
            ),
        ];
        for row in rows {
            let _ = inner.rows.insert(row);
        }
        let _ = inner.placed.insert(head.rid, rows);
    }

    /// Up to `listing.limit` entity ids after `after`, and the place of the
    /// last one when more may follow.
    pub(crate) fn page(
        &self,
        listing: &Listing,
        after: Option<(u64, [u8; 16])>,
    ) -> (Vec<Rid>, Option<(u64, [u8; 16])>) {
        let inner = self.inner.read().unwrap_or_else(PoisonError::into_inner);
        let Some(group) = inner
            .groups
            .get(&(listing.site.clone(), listing.kind.clone()))
            .copied()
        else {
            return (Vec::new(), None);
        };
        let start = match after {
            Some((inv, rid)) => std::ops::Bound::Excluded((group, listing.order, inv, rid)),
            None => std::ops::Bound::Included((group, listing.order, 0, [0; 16])),
        };
        let end = std::ops::Bound::Included((group, listing.order, u64::MAX, [u8::MAX; 16]));
        let mut ids = Vec::with_capacity(listing.limit);
        let mut last = None;
        for &(_, _, inv, rid) in inner.rows.range((start, end)).take(listing.limit + 1) {
            if ids.len() == listing.limit {
                return (ids, last);
            }
            ids.push(Rid::from_bytes(rid));
            last = Some((inv, rid));
        }
        (ids, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::entity::{Entity, Published};

    fn head(n: u8, first: u64, last: u64) -> Head {
        let mut head = Entity::new("post")
            .into_head(
                Rid::from_bytes([n; 16]),
                0,
                crate::content::locale::Locale::EN,
            )
            .unwrap();
        head.first_published_ms = first;
        head.variants[0].published = Some(Published {
            revision: 1,
            at_ms: last,
            path: None,
        });
        head
    }

    #[test]
    fn test_pages_follow_each_order_and_drop_unpublished() {
        let index = ListIndex::new();
        index.update(&head(1, 10, 50));
        index.update(&head(2, 20, 20));
        index.update(&head(3, 30, 30));
        let ids = |listing: &Listing| index.page(listing, None).0;
        let n = |v: Vec<Rid>| v.iter().map(|r| r.as_bytes()[0]).collect::<Vec<_>>();
        assert_eq!(n(ids(&Listing::latest("post"))), [3, 2, 1]);
        assert_eq!(n(ids(&Listing::latest("post").updated())), [1, 3, 2]);
        assert!(ids(&Listing::latest("page")).is_empty());
        assert!(ids(&Listing::latest("post").site("other")).is_empty());

        let first = Listing::latest("post").limit(2);
        let (page, after) = index.page(&first, None);
        assert_eq!(n(page), [3, 2]);
        let (page, after) = index.page(&first, after);
        assert_eq!(n(page), [1]);
        assert!(after.is_none());

        let mut gone = head(2, 20, 20);
        gone.variants[0].published = None;
        index.update(&gone);
        assert_eq!(n(ids(&Listing::latest("post"))), [3, 1]);
    }

    #[test]
    fn test_cursor_text_round_trips_and_rejects_junk() {
        let cursor = Cursor {
            listing: Listing::latest("post").site("a.example").limit(7).updated(),
            after: (99, [5; 16]),
        };
        assert_eq!(Cursor::parse(&cursor.to_string()).unwrap(), cursor);
        for junk in ["", "1.2.3", "9.1.0.00.00.00", "x.y.z.w.v.u"] {
            assert!(Cursor::parse(junk).is_err(), "{junk}");
        }
    }
}
