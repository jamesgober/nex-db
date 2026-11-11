//! The listing index: published entities by site and type, newest first.
//!
//! Derived, like the route index: rebuilt from the entity heads at open and
//! updated as commits apply. Two orders per site and type: by first
//! publication (`latest`) and by the last publish (`updated`), and the same
//! per author and per entity referred to (a term), and translations older
//! than their source per locale. A page is a range read of an ordered set,
//! so a listing never scans entities.
//!
//! Sticky entities have a second row in each order with the top bit of the
//! inverted time cleared, so they sort ahead of every other row. A listing
//! that is not sticky-first starts at the top bit; one that is skips the
//! ordinary rows of sticky entities.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fmt,
    sync::{PoisonError, RwLock},
};

use super::{entity::Head, locale::Locale};
use crate::{
    error::{Error, Result},
    ids::{AccountId, EntityId},
};

/// The most entries one page holds.
pub(crate) const MAX_PAGE: usize = 1000;
/// Entries in a page when no limit is set.
const DEFAULT_PAGE: usize = 100;

const ORDER_LATEST: u8 = 1;
const ORDER_UPDATED: u8 = 2;
/// The top bit of an inverted time: set in every ordinary row (a time in
/// milliseconds is below 2^63), cleared in the rows of sticky entities.
const TOP: u64 = 1 << 63;

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
    pub(crate) filter: Option<Filter>,
    pub(crate) sticky: bool,
}

/// What a listing keeps: entities of an author, entities whose published
/// body refers to an entity (a term), or entities whose translation into a
/// locale is older than their published source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Filter {
    Author(AccountId),
    Refers(EntityId),
    Outdated(Locale),
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
            filter: None,
            sticky: false,
        }
    }

    /// Entities of every type whose translation into `locale` was made
    /// from an older revision than the one their own locale publishes, the
    /// most recently published source first. Its entries are the
    /// translations' working drafts, for translators. Any status.
    pub fn outdated(locale: Locale) -> Listing {
        Listing {
            kind: String::new(),
            site: crate::DEFAULT_SITE.to_owned(),
            order: ORDER_UPDATED,
            limit: DEFAULT_PAGE,
            filter: Some(Filter::Outdated(locale)),
            sticky: false,
        }
    }

    /// Sticky entities ([`Entity::sticky`](crate::Entity::sticky)) first,
    /// in the listing's order, then the others.
    pub fn sticky_first(mut self) -> Listing {
        self.sticky = true;
        self
    }

    /// The order code a cursor carries: 1 and 2, or 3 and 4 when sticky
    /// entities come first.
    fn code(&self) -> u8 {
        self.order + if self.sticky { 2 } else { 0 }
    }

    /// Only entities `account` is an author of
    /// ([`Entity::author`](crate::Entity::author)). Replaces a
    /// [`term`](Self::term) filter.
    pub fn by_author(mut self, account: AccountId) -> Listing {
        self.filter = Some(Filter::Author(account));
        self
    }

    /// Only entities whose published body refers to `term`: a term in a
    /// terms field ([`Type::terms`](crate::Type::terms)), or any entity
    /// referred to, for "posts in this series". Replaces a
    /// [`by_author`](Self::by_author) filter.
    pub fn term(mut self, term: EntityId) -> Listing {
        self.filter = Some(Filter::Refers(term));
        self
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
            self.listing.code(),
            self.listing.limit,
            self.after.0
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
        let (tag, id): (char, &[u8]) = match &self.listing.filter {
            None => return Ok(()),
            Some(Filter::Author(a)) => ('a', a.as_bytes()),
            Some(Filter::Refers(r)) => ('t', r.as_bytes()),
            Some(Filter::Outdated(l)) => ('o', l.as_str().as_bytes()),
        };
        write!(f, ".{tag}")?;
        for b in id {
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
        let (order, limit, inv, rid, site, kind, filter) = match parts.as_slice() {
            [order, limit, inv, rid, site, kind] => (order, limit, inv, rid, site, kind, None),
            [order, limit, inv, rid, site, kind, filter] => {
                (order, limit, inv, rid, site, kind, Some(filter))
            }
            _ => return Err(bad()),
        };
        let filter = match filter {
            Some(text) => {
                let id = |hex: &str| -> Result<[u8; 16]> {
                    unhex(hex).and_then(|b| b.try_into().ok()).ok_or_else(bad)
                };
                match text.split_at_checked(1) {
                    Some(("a", hex)) => Some(Filter::Author(AccountId::from_bytes(id(hex)?))),
                    Some(("t", hex)) => Some(Filter::Refers(EntityId::from_bytes(id(hex)?))),
                    Some(("o", hex)) => {
                        let tag =
                            String::from_utf8(unhex(hex).ok_or_else(bad)?).map_err(|_| bad())?;
                        Some(Filter::Outdated(Locale::new(&tag).map_err(|_| bad())?))
                    }
                    _ => return Err(bad()),
                }
            }
            None => None,
        };
        let code: u8 = order.parse().map_err(|_| bad())?;
        if !(1..=4).contains(&code) {
            return Err(bad());
        }
        let (order, sticky) = ((code - 1) % 2 + 1, code > 2);
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
                filter,
                sticky,
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

/// A group of rows: site, type, and filter (none for every entity).
type Group = (String, String, Option<Filter>);

#[derive(Debug, Default)]
struct Inner {
    rows: BTreeSet<Row>,
    /// The group number of each (site, type, filter).
    groups: HashMap<Group, u32>,
    /// Each listed entity's rows, to remove them when it changes.
    placed: HashMap<EntityId, Vec<Row>>,
    /// The listed entities that are sticky.
    sticky: HashSet<[u8; 16]>,
}

impl Inner {
    fn group(&mut self, key: Group) -> u32 {
        let next = self.groups.len() as u32;
        *self.groups.entry(key).or_insert(next)
    }
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

    /// Drop `rid` from every listing.
    pub(crate) fn remove(&self, rid: EntityId) {
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(rows) = inner.placed.remove(&rid) {
            for row in rows {
                let _ = inner.rows.remove(&row);
            }
        }
        let _ = inner.sticky.remove(rid.as_bytes());
    }

    /// Place `head` as it now is: listed when published, not otherwise.
    pub(crate) fn update(&self, head: &Head) {
        self.remove(head.rid);
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        if !head.is_published() {
            return;
        }
        let rid = *head.rid.as_bytes();
        let latest = u64::MAX - head.first_published_ms;
        let updated = u64::MAX - head.last_published_ms();
        // Every entity a published body refers to.
        let refers = super::entity::ref_set(
            head.variants
                .iter()
                .filter_map(|v| v.published.as_ref())
                .flat_map(|p| p.refs.iter().copied()),
        );
        let filters = std::iter::once(None)
            .chain(head.authors.iter().map(|a| Some(Filter::Author(*a))))
            .chain(refers.into_iter().map(|r| Some(Filter::Refers(r))));
        let mut rows = Vec::with_capacity(2 + 2 * head.authors.len());
        for filter in filters {
            let group = inner.group((head.site.clone(), head.kind.clone(), filter));
            rows.push((group, ORDER_LATEST, latest, rid));
            rows.push((group, ORDER_UPDATED, updated, rid));
        }
        // Translations made from an older revision than the source
        // publishes.
        if let Some(source) = head.base().published.as_ref() {
            for v in head.variants.iter().skip(1) {
                if v.source < source.revision {
                    let filter = Some(Filter::Outdated(v.locale));
                    let group = inner.group((head.site.clone(), String::new(), filter));
                    rows.push((group, ORDER_UPDATED, updated, rid));
                }
            }
        }
        if head.sticky {
            let ahead: Vec<Row> = rows
                .iter()
                .map(|&(g, o, inv, r)| (g, o, inv & !TOP, r))
                .collect();
            rows.extend(ahead);
            let _ = inner.sticky.insert(rid);
        }
        for row in &rows {
            let _ = inner.rows.insert(*row);
        }
        let _ = inner.placed.insert(head.rid, rows);
    }

    /// Up to `listing.limit` entity ids after `after`, and the place of the
    /// last one when more may follow.
    pub(crate) fn page(
        &self,
        listing: &Listing,
        after: Option<(u64, [u8; 16])>,
    ) -> (Vec<EntityId>, Option<(u64, [u8; 16])>) {
        let inner = self.inner.read().unwrap_or_else(PoisonError::into_inner);
        let Some(group) = inner
            .groups
            .get(&(listing.site.clone(), listing.kind.clone(), listing.filter))
            .copied()
        else {
            return (Vec::new(), None);
        };
        let first = if listing.sticky { 0 } else { TOP };
        let start = match after {
            Some((inv, rid)) => {
                std::ops::Bound::Excluded((group, listing.order, inv.max(first), rid))
            }
            None => std::ops::Bound::Included((group, listing.order, first, [0; 16])),
        };
        let end = std::ops::Bound::Included((group, listing.order, u64::MAX, [u8::MAX; 16]));
        let mut ids = Vec::with_capacity(listing.limit);
        let mut last = None;
        let rows = inner
            .rows
            .range((start, end))
            // The ordinary row of a sticky entity, already listed ahead.
            .filter(|(_, _, inv, rid)| {
                !(listing.sticky && inv & TOP != 0 && inner.sticky.contains(rid))
            });
        for &(_, _, inv, rid) in rows.take(listing.limit + 1) {
            if ids.len() == listing.limit {
                return (ids, last);
            }
            ids.push(EntityId::from_bytes(rid));
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
                EntityId::from_bytes([n; 16]),
                0,
                crate::content::locale::Locale::EN,
            )
            .unwrap();
        head.first_published_ms = first;
        head.variants[0].published = Some(Published {
            revision: 1,
            at_ms: last,
            path: None,
            refs: Vec::new(),
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
        let n = |v: Vec<EntityId>| v.iter().map(|r| r.as_bytes()[0]).collect::<Vec<_>>();
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

        // By author.
        let ann = AccountId::from_bytes([9; 16]);
        let mut by_ann = head(4, 40, 40);
        by_ann.authors = vec![ann];
        index.update(&by_ann);
        assert_eq!(n(ids(&Listing::latest("post").by_author(ann))), [4]);
        assert_eq!(n(ids(&Listing::latest("post"))), [4, 3, 2, 1]);
        by_ann.authors.clear();
        index.update(&by_ann);
        assert!(ids(&Listing::latest("post").by_author(ann)).is_empty());
        // By an entity a published body refers to.
        let tag = EntityId::from_bytes([7; 16]);
        if let Some(p) = by_ann.variants[0].published.as_mut() {
            p.refs = vec![tag];
        }
        index.update(&by_ann);
        assert_eq!(n(ids(&Listing::latest("post").term(tag))), [4]);
        index.remove(by_ann.rid);
        assert!(ids(&Listing::latest("post").term(tag)).is_empty());

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
        let by = Cursor {
            listing: Listing::latest("post").by_author(AccountId::from_bytes([3; 16])),
            after: (1, [2; 16]),
        };
        assert_eq!(Cursor::parse(&by.to_string()).unwrap(), by);
        let term = Cursor {
            listing: Listing::latest("post").term(EntityId::from_bytes([4; 16])),
            after: (1, [2; 16]),
        };
        assert_eq!(Cursor::parse(&term.to_string()).unwrap(), term);
        assert!(Cursor::parse(&format!("{term}").replace(".t", ".x")).is_err());
        for junk in ["", "1.2.3", "9.1.0.00.00.00", "x.y.z.w.v.u"] {
            assert!(Cursor::parse(junk).is_err(), "{junk}");
        }
    }
}
