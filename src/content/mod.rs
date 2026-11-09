//! The content engine: entities, their drafts and revisions, and routes.
//!
//! Entities live in an lsm-db store in `content/store/` (its own write-ahead
//! log is off: the commit log is the write-ahead log). Per entity the store
//! keeps a head (identity, the working draft, what is published) and its
//! fixed revisions. Routes are stored too, so the route index is rebuilt at
//! open from them alone, and `apply` updates the index in the same commit as
//! the entity it points to.
//!
//! Staging computes every record a commit writes (heads, revisions, routes);
//! `apply` stores them as they are, so a replay writes the same bytes.

pub(crate) mod entity;
pub(crate) mod lists;
pub(crate) mod locale;
mod routes;
pub(crate) mod schedule;
mod tree;
pub(crate) mod types;

use std::{
    collections::{HashMap, HashSet},
    fmt,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, PoisonError, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::SystemTime,
};

use lsm_db::{Batch, Lsm};

use self::{
    entity::{
        Action, Body, Entity, Entry, Head, Patch, Published, Revision, RevisionInfo, RouteEntry,
        RouteKind, Status, Visibility, decode_route, encode_route, ref_set,
    },
    lists::{Cursor, ListIndex, Listing, Page},
    locale::{Locale, SpaceSpec},
    routes::RouteTable,
    schedule::{Schedules, Wake},
    tree::Tree,
    types::{Rule, Type, TypeIndex, Types},
};
use crate::{
    Database,
    core::{
        codec::{Reader, Writer},
        conflict::ConflictTable,
        now_ms,
        pipeline::SnapshotGuard,
        record::{Section, Seq},
        versions::Versions,
    },
    engine::{Conflict, Engine, EngineId, Staged},
    error::{Error, Result},
    feed::Change,
    ids::{AccountId, Rid},
};

/// Deepest a page tree goes: an entity has at most 64 ancestors.
const MAX_DEPTH: usize = 64;

/// Conflict key of an entity's place in the page tree: written by a parent
/// change for the entity and each ancestor of its new parent, so two
/// concurrent changes that together make a cycle never both land.
fn tree_conflict(rid: Rid) -> Vec<u8> {
    let mut key = Vec::with_capacity(17);
    key.push(b'p');
    key.extend_from_slice(rid.as_bytes());
    key
}

/// Section format 1 (0.1 to 0.3): create operations only. Read, never
/// written.
const FORMAT_CREATE_ONLY: u16 = 1;
/// Section format 2, written from 0.4.
const FORMAT: u16 = 2;

/// Create an entity from a 0.1 to 0.3 record (format 1 sections only).
const OP_CREATE: u8 = 1;
/// Store an entity's head.
const OP_PUT_HEAD: u8 = 2;
/// Store a fixed revision.
const OP_PUT_REVISION: u8 = 3;
/// Set a route.
const OP_PUT_ROUTE: u8 = 4;
/// Remove a route.
const OP_DELETE_ROUTE: u8 = 5;
/// Replace the space's settings.
const OP_SET_SPACE: u8 = 6;
/// Replace the space's types.
const OP_SET_TYPES: u8 = 7;
/// Remove an entity and its revisions.
const OP_DELETE_ENTITY: u8 = 8;
/// Record that an entity refers to another.
const OP_PUT_LINK: u8 = 9;
/// Remove such a record.
const OP_DELETE_LINK: u8 = 10;

/// Most entities one delete removes, counting those it cascades to.
const MAX_CASCADE: usize = 1000;

/// The status an entity's old path redirects with when the path changes.
const MOVED: u16 = 301;

/// Key of the store's applied-through mark.
const META_APPLIED: &[u8] = b"\0meta/applied";

fn prefix(collection: u32, tag: u8) -> Vec<u8> {
    let mut key = Vec::with_capacity(48);
    key.extend_from_slice(&collection.to_be_bytes());
    key.push(tag);
    key
}

fn entity_prefix(collection: u32) -> Vec<u8> {
    prefix(collection, b'e')
}

fn entity_key(collection: u32, rid: Rid) -> Vec<u8> {
    let mut key = entity_prefix(collection);
    key.extend_from_slice(rid.as_bytes());
    key
}

fn revision_prefix(collection: u32, rid: Rid) -> Vec<u8> {
    let mut key = prefix(collection, b'v');
    key.extend_from_slice(rid.as_bytes());
    key
}

fn revision_key(collection: u32, rid: Rid, n: u32) -> Vec<u8> {
    let mut key = revision_prefix(collection, rid);
    key.extend_from_slice(&n.to_be_bytes());
    key
}

fn link_prefix(collection: u32, target: Rid) -> Vec<u8> {
    let mut key = prefix(collection, b'b');
    key.extend_from_slice(target.as_bytes());
    key
}

/// The stored record that `source` refers to `target`: found by a scan of
/// the target's prefix.
fn link_key(collection: u32, target: Rid, source: Rid) -> Vec<u8> {
    let mut key = link_prefix(collection, target);
    key.extend_from_slice(source.as_bytes());
    key
}

/// Conflict key of the references to `target`: written by a commit that
/// adds one and by a commit that deletes the target, so the two never
/// both land.
fn link_conflict(target: Rid) -> Vec<u8> {
    let mut key = Vec::with_capacity(17);
    key.push(b'l');
    key.extend_from_slice(target.as_bytes());
    key
}

fn space_key(collection: u32) -> Vec<u8> {
    prefix(collection, b'm')
}

/// Conflict key of the space's settings.
const SPACE_CONFLICT_KEY: &[u8] = b"m";

fn types_key(collection: u32) -> Vec<u8> {
    prefix(collection, b't')
}

/// Conflict key of the space's types.
const TYPES_CONFLICT_KEY: &[u8] = b"t";

fn route_prefix(collection: u32) -> Vec<u8> {
    prefix(collection, b'r')
}

fn stored_route_key(collection: u32, site: &str, path: &str) -> Vec<u8> {
    let mut key = route_prefix(collection);
    key.extend_from_slice(site.as_bytes());
    key.push(0);
    key.extend_from_slice(path.as_bytes());
    key
}

/// Conflict-table key for a route.
fn route_key(site: &str, path: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + site.len() + path.len());
    key.push(b'r');
    key.extend_from_slice(site.as_bytes());
    key.push(0);
    key.extend_from_slice(path.as_bytes());
    key
}

/// The end of a prefix scan: the prefix with its last byte raised.
fn after(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < u8::MAX {
            end.push(last + 1);
            break;
        }
    }
    end
}

/// The content engine.
pub(crate) struct ContentEngine {
    collection: u32,
    dir: PathBuf,
    store: Lsm,
    /// Highest seq the store holds (in memory or on disk).
    applied: AtomicU64,
    /// Highest seq the store holds on disk: the mark at the last flush.
    durable: AtomicU64,
    /// Keeps a checkpoint's mark from interleaving with an apply's batch.
    writing: Mutex<()>,
    routes: RouteTable,
    /// Published entities by site and type.
    lists: ListIndex,
    /// Children by parent.
    tree: Tree,
    /// Every schedule, earliest first.
    schedules: Schedules,
    /// The space's default locale and fallback chains.
    space: RwLock<SpaceSpec>,
    /// The space's types, and what they index.
    types: RwLock<Types>,
    type_index: Mutex<TypeIndex>,
    /// Entity head versions kept for running snapshots.
    versions: Versions,
    conflicts: ConflictTable,
    /// The latest publication time given out or stored: each publication
    /// is later than it, so listings follow publication order even when
    /// the system clock steps back.
    published_ms: AtomicU64,
}

impl fmt::Debug for ContentEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContentEngine")
            .field("collection", &self.collection)
            .field("applied", &self.applied.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl ContentEngine {
    /// Open the store in `dir` and rebuild the route index from it.
    pub(crate) fn open(dir: &Path, collection: u32, wake: Arc<Wake>) -> Result<Self> {
        let store = Lsm::open(dir)?;
        let applied = match store.get(META_APPLIED)? {
            Some(bytes) => {
                let bytes: [u8; 8] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::corrupt("the content store mark", 0))?;
                u64::from_le_bytes(bytes)
            }
            None => 0,
        };
        let routes = RouteTable::new();
        let lists = ListIndex::new();
        let tree = Tree::new();
        let schedules = Schedules::new(wake);
        let types = match store.get(types_key(collection))? {
            Some(bytes) => Types::decode(&bytes, applied)?,
            None => Types::default(),
        };
        let mut type_index = TypeIndex::default();
        // Every head goes into the listing index. Entities stored by 0.1 to
        // 0.3 have no route records: their routes come from the entities.
        // Nor do they, or heads of the format before, have reference
        // records: those are written now, from the heads.
        let mut links = Batch::new();
        let mut any_links = false;
        let mut published_ms = 0;
        let start = entity_prefix(collection);
        for (_, value) in store.scan(start.clone()..after(&start))? {
            let head = Head::decode(&value, applied)?;
            lists.update(&head);
            tree.update(&head);
            schedules.update(&head);
            published_ms = published_ms.max(head.last_published_ms());
            let legacy = Head::is_legacy(&value);
            type_index.update(&types, &head, |locale, n| {
                published_body(&store, collection, &head, legacy, locale, n)
            })?;
            if !Head::is_current(&value) {
                for target in head.refs() {
                    links.put(link_key(collection, target, head.rid), []);
                    any_links = true;
                }
            }
            if Head::is_legacy(&value) {
                let base = head.base();
                if let Some(path) = base.draft.path.as_deref() {
                    routes.set(&head.site, path, 0, Some(page(&head, base.locale, 1)));
                }
            }
        }
        let start = route_prefix(collection);
        for (key, value) in store.scan(start.clone()..after(&start))? {
            let name = key.get(start.len()..).unwrap_or_default();
            let (site, path) = split_route(name, applied)?;
            routes.set(site, path, 0, Some(decode_route(&value, applied)?));
        }
        let space = match store.get(space_key(collection))? {
            Some(bytes) => SpaceSpec::decode(&bytes, applied)?,
            None => SpaceSpec::default(),
        };
        if any_links {
            store.write(links)?;
        }
        Ok(ContentEngine {
            collection,
            dir: dir.to_path_buf(),
            store,
            applied: AtomicU64::new(applied),
            durable: AtomicU64::new(applied),
            writing: Mutex::new(()),
            routes,
            lists,
            tree,
            schedules,
            space: RwLock::new(space),
            types: RwLock::new(types),
            type_index: Mutex::new(type_index),
            versions: Versions::new(),
            conflicts: ConflictTable::new(),
            published_ms: AtomicU64::new(published_ms),
        })
    }

    /// A publication time: now, or a millisecond after the latest one when
    /// the clock reads earlier.
    fn publish_ms(&self) -> u64 {
        let now = now_ms();
        let mut last = self.published_ms.load(Ordering::Acquire);
        loop {
            let next = now.max(last.saturating_add(1));
            match self.published_ms.compare_exchange_weak(
                last,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return next,
                Err(seen) => last = seen,
            }
        }
    }

    /// The space this engine holds.
    pub(crate) fn collection(&self) -> u32 {
        self.collection
    }

    /// Take `definition` (as the catalog holds it): the settings a new
    /// space starts with, until `set_space` stores others.
    pub(crate) fn adopt(&self, definition: &[u8]) -> Result<()> {
        if definition.is_empty() || self.store.get(space_key(self.collection))?.is_some() {
            return Ok(());
        }
        *self.space.write().unwrap_or_else(PoisonError::into_inner) =
            SpaceSpec::decode(definition, 0)?;
        Ok(())
    }

    /// The stored head bytes of `rid` as a snapshot at `at` sees them.
    fn head_bytes_at(&self, rid: Rid, at: Seq) -> Result<Option<Vec<u8>>> {
        let key = entity_key(self.collection, rid);
        match self.versions.at(&key, at) {
            Some(value) => Ok(value.map(|v| v.to_vec())),
            None => Ok(self.store.get(&key)?),
        }
    }

    fn head_at(&self, rid: Rid, at: Seq) -> Result<Option<Head>> {
        self.head_bytes_at(rid, at)?
            .map(|bytes| Head::decode(&bytes, at))
            .transpose()
    }

    /// The head of `rid` as the store holds it. A head an apply in
    /// progress recorded for snapshots, but has not written yet, is not
    /// seen: its revision may not be in the store yet.
    fn head(&self, rid: Rid) -> Result<Option<Head>> {
        self.head_at(rid, self.latest())
    }

    /// The newest commit the store holds.
    fn latest(&self) -> Seq {
        self.applied.load(Ordering::Acquire)
    }

    fn revision(&self, rid: Rid, n: u32) -> Result<Option<Revision>> {
        self.store
            .get(revision_key(self.collection, rid, n))?
            .map(|bytes| Revision::decode(&bytes, 0))
            .transpose()
    }

    fn types(&self) -> Types {
        self.types
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn type_index(&self) -> std::sync::MutexGuard<'_, TypeIndex> {
        self.type_index
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The entities whose stored references name `target`.
    fn stored_referrers(&self, target: Rid) -> Result<Vec<Rid>> {
        let start = link_prefix(self.collection, target);
        self.store
            .scan(start.clone()..after(&start))?
            .map(|(key, _)| {
                key.get(start.len()..)
                    .and_then(|b| <[u8; 16]>::try_from(b).ok())
                    .map(Rid::from_bytes)
                    .ok_or_else(|| Error::corrupt("a reference key", 0))
            })
            .collect()
    }

    /// Every head in the store, each with whether it is a record from 0.1
    /// to 0.3.
    fn all_heads(&self) -> Result<Vec<(Head, bool)>> {
        let start = entity_prefix(self.collection);
        self.store
            .scan(start.clone()..after(&start))?
            .map(|(_, value)| Ok((Head::decode(&value, 0)?, Head::is_legacy(&value))))
            .collect()
    }

    /// The space's settings.
    fn space(&self) -> SpaceSpec {
        self.space
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The published entry of `rid` as a snapshot at `at` sees it: in
    /// `asked` (the space's default locale when `None`), else along its
    /// fallback chain, else in the entity's own locale.
    fn published_in(&self, rid: Rid, asked: Option<Locale>, at: Seq) -> Result<Option<Entry>> {
        let Some(bytes) = self.head_bytes_at(rid, at)? else {
            return Ok(None);
        };
        let head = Head::decode(&bytes, at)?;
        let space = self.space();
        let asked = asked.unwrap_or(space.default_locale);
        let found = space
            .order(asked)
            .chain(std::iter::once(head.base().locale))
            .find_map(|l| {
                head.variant(l)
                    .and_then(|v| v.published.clone().map(|p| (v, p)))
            });
        let Some((variant, published)) = found else {
            return Ok(None);
        };
        // A record from 0.1 to 0.3 is its own published body.
        let mut body = if Head::is_legacy(&bytes) {
            variant.draft.clone()
        } else {
            match self.revision(rid, published.revision)? {
                Some(revision) => revision.body,
                // A delete that applied after the snapshot's head was read
                // removes the revisions with the head.
                None if self.store.get(entity_key(self.collection, rid))?.is_none() => {
                    return Ok(None);
                }
                None => return Err(Error::corrupt("an entity without its revision", at)),
            }
        };
        // The path can move without a new revision.
        body.path = published.path;
        Ok(Some(head.entry(
            variant.locale,
            published.revision,
            body,
            Some(asked),
        )))
    }

    /// The working draft of `rid` in `locale` (its own when `None`).
    fn draft_in(&self, rid: Rid, locale: Option<Locale>, at: Seq) -> Result<Option<Entry>> {
        Ok(self.head_at(rid, at)?.and_then(|head| {
            let variant = match locale {
                Some(l) => head.variant(l)?,
                None => head.base(),
            };
            Some(head.entry(
                variant.locale,
                head.last_revision,
                variant.draft.clone(),
                None,
            ))
        }))
    }

    fn revisions(&self, rid: Rid) -> Result<Vec<RevisionInfo>> {
        let start = revision_prefix(self.collection, rid);
        let mut out = Vec::new();
        for (key, value) in self.store.scan(start.clone()..after(&start))? {
            let n = key
                .get(start.len()..)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(u32::from_be_bytes)
                .ok_or_else(|| Error::corrupt("a revision key", 0))?;
            let revision = Revision::decode(&value, 0)?;
            out.push(RevisionInfo {
                number: n,
                locale: revision.locale,
                at_ms: revision.at_ms,
                message: revision.message,
            });
        }
        Ok(out)
    }
}

fn split_route(name: &[u8], at: Seq) -> Result<(&str, &str)> {
    let corrupt = || Error::corrupt("a route key", at);
    let zero = name.iter().position(|b| *b == 0).ok_or_else(corrupt)?;
    let site = std::str::from_utf8(&name[..zero]).map_err(|_| corrupt())?;
    let path = std::str::from_utf8(&name[zero + 1..]).map_err(|_| corrupt())?;
    Ok((site, path))
}

/// The body of revision `n`, published in `locale` of `head`: the stored
/// revision, or for a record from 0.1 to 0.3 (`legacy`), its draft.
fn published_body(
    store: &Lsm,
    collection: u32,
    head: &Head,
    legacy: bool,
    locale: Locale,
    n: u32,
) -> Result<Body> {
    if legacy {
        return head
            .variant(locale)
            .map(|v| v.draft.clone())
            .ok_or_else(|| Error::corrupt("an entity record", 0));
    }
    match store.get(revision_key(collection, head.rid, n))? {
        Some(bytes) => Ok(Revision::decode(&bytes, 0)?.body),
        None => Err(Error::corrupt("an entity without its revision", 0)),
    }
}

/// The page route of `head` in `locale` at `revision`.
fn page(head: &Head, locale: Locale, revision: u32) -> RouteEntry {
    RouteEntry {
        entity: head.rid,
        revision,
        kind: RouteKind::Page,
        visibility: head.visibility,
        locale,
    }
}

/// One operation as read from a section.
enum Op<'a> {
    Create(&'a [u8]),
    PutHead(Rid, &'a [u8]),
    PutRevision(Rid, u32, &'a [u8]),
    PutRoute(&'a str, &'a str, &'a [u8]),
    DeleteRoute(&'a str, &'a str),
    SetSpace(&'a [u8]),
    SetTypes(&'a [u8]),
    DeleteEntity(Rid),
    PutLink(Rid, Rid),
    DeleteLink(Rid, Rid),
}

fn decode_ops(seq: Seq, format: u16, body: &[u8]) -> Result<Vec<Op<'_>>> {
    let mut r = Reader::new(body, "a content section", seq);
    let mut ops = Vec::new();
    while !r.is_empty() {
        let op = match (format, r.u8()?) {
            (FORMAT_CREATE_ONLY, OP_CREATE) => Op::Create(r.bytes32()?),
            (FORMAT, OP_PUT_HEAD) => Op::PutHead(Rid::from_bytes(r.fixed()?), r.bytes32()?),
            (FORMAT, OP_PUT_REVISION) => {
                Op::PutRevision(Rid::from_bytes(r.fixed()?), r.u32()?, r.bytes32()?)
            }
            (FORMAT, OP_PUT_ROUTE) => Op::PutRoute(r.str16()?, r.str16()?, r.bytes16()?),
            (FORMAT, OP_DELETE_ROUTE) => Op::DeleteRoute(r.str16()?, r.str16()?),
            (FORMAT, OP_SET_SPACE) => Op::SetSpace(r.bytes16()?),
            (FORMAT, OP_SET_TYPES) => Op::SetTypes(r.bytes32()?),
            (FORMAT, OP_DELETE_ENTITY) => Op::DeleteEntity(Rid::from_bytes(r.fixed()?)),
            (FORMAT, OP_PUT_LINK) => {
                Op::PutLink(Rid::from_bytes(r.fixed()?), Rid::from_bytes(r.fixed()?))
            }
            (FORMAT, OP_DELETE_LINK) => {
                Op::DeleteLink(Rid::from_bytes(r.fixed()?), Rid::from_bytes(r.fixed()?))
            }
            _ => return Err(Error::corrupt("a content operation", seq)),
        };
        ops.push(op);
    }
    Ok(ops)
}

impl Engine for ContentEngine {
    fn id(&self) -> EngineId {
        EngineId::CONTENT
    }

    fn name(&self) -> &'static str {
        "content"
    }

    fn format(&self) -> u16 {
        FORMAT
    }

    fn define(&self, definition: &[u8]) -> Result<()> {
        // A space's definition is the settings it starts with; empty for
        // the defaults.
        if definition.is_empty() {
            return Ok(());
        }
        SpaceSpec::decode(definition, 0)
            .map(|_| ())
            .map_err(|_| Error::invalid("space definition", "not space settings"))
    }

    fn apply(&self, seq: Seq, section: &Section<'_>, changes: &mut Vec<Change>) -> Result<()> {
        let known = section.format == FORMAT || section.format == FORMAT_CREATE_ONLY;
        if !known || section.flags != 0 || section.collection != self.collection {
            return Err(Error::corrupt("a content section header", seq));
        }
        if seq <= self.applied.load(Ordering::Acquire) {
            return Ok(());
        }
        let ops = decode_ops(seq, section.format, section.body)?;
        let mut batch = Batch::new();
        let mut routes: Vec<(String, String, Option<RouteEntry>)> = Vec::new();
        let mut heads = Vec::new();
        let mut space = None;
        let mut types = None;
        let mut deleted = Vec::new();
        for op in &ops {
            match op {
                Op::Create(record) => {
                    let head = Head::decode(record, seq)?;
                    let key = entity_key(self.collection, head.rid);
                    self.versions
                        .record(&key, seq, Some(record), || Ok(self.store.get(&key)?))?;
                    batch.put(key, record);
                    for target in head.refs() {
                        batch.put(link_key(self.collection, target, head.rid), []);
                    }
                    changes.push(Change::EntityChanged {
                        rid: head.rid,
                        revision: 1,
                    });
                    let base = head.base();
                    if let Some(path) = base.draft.path.as_deref() {
                        let entry = page(&head, base.locale, 1);
                        let stored = stored_route_key(self.collection, &head.site, path);
                        batch.put(stored, encode_route(&entry));
                        routes.push((head.site.clone(), path.to_owned(), Some(entry)));
                    }
                    heads.push((head, true));
                }
                Op::PutHead(rid, value) => {
                    let key = entity_key(self.collection, *rid);
                    self.versions
                        .record(&key, seq, Some(value), || Ok(self.store.get(&key)?))?;
                    batch.put(key, *value);
                    let head = Head::decode(value, seq)?;
                    // A head of the format before records no references
                    // in its section.
                    if !Head::is_current(value) {
                        for target in head.refs() {
                            batch.put(link_key(self.collection, target, head.rid), []);
                        }
                    }
                    changes.push(Change::EntityChanged {
                        rid: *rid,
                        revision: head.base().published.as_ref().map_or(0, |p| p.revision),
                    });
                    heads.push((head, false));
                }
                Op::PutRevision(rid, n, value) => {
                    batch.put(revision_key(self.collection, *rid, *n), *value);
                }
                Op::PutRoute(site, path, value) => {
                    let entry = decode_route(value, seq)?;
                    batch.put(stored_route_key(self.collection, site, path), *value);
                    routes.push(((*site).to_owned(), (*path).to_owned(), Some(entry)));
                }
                Op::DeleteRoute(site, path) => {
                    batch.delete(stored_route_key(self.collection, site, path));
                    routes.push(((*site).to_owned(), (*path).to_owned(), None));
                }
                Op::SetSpace(value) => {
                    space = Some(SpaceSpec::decode(value, seq)?);
                    batch.put(space_key(self.collection), *value);
                }
                Op::SetTypes(value) => {
                    types = Some(Types::decode(value, seq)?);
                    batch.put(types_key(self.collection), *value);
                }
                Op::DeleteEntity(rid) => {
                    let key = entity_key(self.collection, *rid);
                    let old = self.store.get(&key)?;
                    if let Some(old) = &old {
                        deleted.push((*rid, Head::decode(old, seq)?.kind));
                    }
                    self.versions.record(&key, seq, None, || Ok(old.clone()))?;
                    batch.delete(key);
                    let start = revision_prefix(self.collection, *rid);
                    for (rev, _) in self.store.scan(start.clone()..after(&start))? {
                        batch.delete(rev);
                    }
                    changes.push(Change::EntityChanged {
                        rid: *rid,
                        revision: 0,
                    });
                }
                Op::PutLink(target, source) => {
                    batch.put(link_key(self.collection, *target, *source), []);
                }
                Op::DeleteLink(target, source) => {
                    batch.delete(link_key(self.collection, *target, *source));
                }
            }
        }
        batch.put(META_APPLIED, seq.to_le_bytes());
        {
            let _writing = self.writing.lock().unwrap_or_else(PoisonError::into_inner);
            self.store.write(batch)?;
            self.applied.store(seq, Ordering::Release);
        }
        for (site, path, entry) in routes {
            self.routes.set(&site, &path, seq, entry);
            changes.push(Change::RouteChanged { site, path });
        }
        for (head, _) in &heads {
            self.lists.update(head);
            self.tree.update(head);
            self.schedules.update(head);
            let _ = self
                .published_ms
                .fetch_max(head.last_published_ms(), Ordering::AcqRel);
        }
        for (rid, kind) in &deleted {
            self.lists.remove(*rid);
            self.tree.remove(*rid);
            self.schedules.remove(*rid);
            self.type_index().remove(*rid, kind);
        }
        if let Some(space) = space {
            *self.space.write().unwrap_or_else(PoisonError::into_inner) = space;
        }
        if let Some(types) = types {
            // New unique fields index entities already stored.
            let mut index = TypeIndex::default();
            for (head, legacy) in self.all_heads()? {
                index.update(&types, &head, |locale, n| {
                    published_body(&self.store, self.collection, &head, legacy, locale, n)
                })?;
            }
            *self.type_index() = index;
            *self.types.write().unwrap_or_else(PoisonError::into_inner) = types;
        } else if !heads.is_empty() {
            // After the write: a revision this commit published is stored.
            let types = self.types();
            let mut index = self.type_index();
            for (head, legacy) in &heads {
                index.update(&types, head, |locale, n| {
                    published_body(&self.store, self.collection, head, *legacy, locale, n)
                })?;
            }
        }
        Ok(())
    }

    fn durable_through(&self) -> Seq {
        self.durable.load(Ordering::Acquire)
    }

    fn checkpoint(&self, upto: Seq) -> Result<Seq> {
        // The store holds every content section through `upto`; say so in
        // its mark, so a store untouched by recent commits does not hold the
        // log back.
        let mark = {
            let _writing = self.writing.lock().unwrap_or_else(PoisonError::into_inner);
            let mark = upto.max(self.applied.load(Ordering::Acquire));
            let mut batch = Batch::new();
            batch.put(META_APPLIED, mark.to_le_bytes());
            self.store.write(batch)?;
            self.applied.store(mark, Ordering::Release);
            mark
        };
        self.store.flush()?;
        crate::core::fs::sync_names(&self.dir)?;
        let _ = self.durable.fetch_max(mark, Ordering::AcqRel);
        Ok(mark)
    }

    fn reclaim(&self, watermark: Seq) {
        self.conflicts.prune(watermark);
        self.versions.prune(watermark);
        self.routes.prune(watermark);
    }
}

/// An operation staged in a transaction.
#[derive(Debug)]
enum StagedOp {
    Revision(Rid, u32, Vec<u8>),
    Route(String, String, Option<RouteEntry>),
    Space(Vec<u8>),
    Types(Vec<u8>),
    Delete(Rid),
}

/// One transaction's content work.
pub(crate) struct ContentStaged<'e> {
    engine: &'e ContentEngine,
    /// Heads as this work left them, in the order first touched.
    heads: Vec<Head>,
    ops: Vec<StagedOp>,
    /// Revisions this work recorded, by entity and number.
    revisions: HashMap<(Rid, u32), (Locale, Body)>,
    /// Routes as this work left them.
    routes: HashMap<(String, String), Option<RouteEntry>>,
    /// The space's types as this work left them.
    types: Option<Types>,
    /// Unique values this work published, and the entity holding each.
    unique: HashMap<Vec<u8>, Rid>,
    /// References this work added (`true`) or removed, by target and
    /// source.
    links: HashMap<(Rid, Rid), bool>,
    /// Entities this work deleted.
    deleted: HashSet<Rid>,
    writes: Vec<Vec<u8>>,
    /// Checked at commit as well as the writes: a serializable commit.
    serializable: bool,
    /// Conflict keys of what this work read, when serializable.
    reads: std::sync::Mutex<Vec<Vec<u8>>>,
}

impl<'e> ContentStaged<'e> {
    pub(crate) fn new(engine: &'e ContentEngine) -> Self {
        ContentStaged {
            engine,
            heads: Vec::new(),
            ops: Vec::new(),
            revisions: HashMap::new(),
            routes: HashMap::new(),
            types: None,
            unique: HashMap::new(),
            links: HashMap::new(),
            deleted: HashSet::new(),
            writes: Vec::new(),
            serializable: false,
            reads: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Make the commit serializable: what this work reads is checked too.
    pub(crate) fn serializable(mut self, on: bool) -> Self {
        self.serializable = on;
        self
    }

    /// Note that this work read the item conflict key `key` names.
    fn note(&self, key: Vec<u8>) {
        if self.serializable {
            self.reads
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(key);
        }
    }
}

impl Staged for ContentStaged<'_> {
    fn engine(&self) -> EngineId {
        EngineId::CONTENT
    }

    fn collection(&self) -> u32 {
        self.engine.collection
    }

    fn is_empty(&self) -> bool {
        self.heads.is_empty() && self.ops.is_empty() && self.links.is_empty()
    }

    fn validate_reads(&self, snapshot: Seq) -> std::result::Result<(), Conflict> {
        let reads = self
            .reads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self
            .engine
            .conflicts
            .conflicts(reads.iter().map(Vec::as_slice), snapshot)
        {
            Err(Conflict)
        } else {
            Ok(())
        }
    }

    fn validate(&self, snapshot: Seq) -> std::result::Result<(), Conflict> {
        if self
            .engine
            .conflicts
            .conflicts(self.writes.iter().map(Vec::as_slice), snapshot)
        {
            Err(Conflict)
        } else {
            Ok(())
        }
    }

    fn reserve(&self, seq: Seq) {
        self.engine
            .conflicts
            .record(self.writes.iter().map(Vec::as_slice), seq);
    }

    fn encode(&self, _seq: Seq, out: &mut Vec<u8>) -> Result<()> {
        let mut w = Writer::new(out);
        for op in &self.ops {
            match op {
                StagedOp::Revision(rid, n, value) => {
                    w.u8(OP_PUT_REVISION);
                    w.bytes(rid.as_bytes());
                    w.u32(*n);
                    w.bytes32(value)?;
                }
                StagedOp::Route(site, path, Some(entry)) => {
                    w.u8(OP_PUT_ROUTE);
                    w.str16(site)?;
                    w.str16(path)?;
                    w.bytes16(&encode_route(entry))?;
                }
                StagedOp::Route(site, path, None) => {
                    w.u8(OP_DELETE_ROUTE);
                    w.str16(site)?;
                    w.str16(path)?;
                }
                StagedOp::Space(value) => {
                    w.u8(OP_SET_SPACE);
                    w.bytes16(value)?;
                }
                StagedOp::Types(value) => {
                    w.u8(OP_SET_TYPES);
                    w.bytes32(value)?;
                }
                StagedOp::Delete(rid) => {
                    w.u8(OP_DELETE_ENTITY);
                    w.bytes(rid.as_bytes());
                }
            }
        }
        let mut links: Vec<_> = self.links.iter().collect();
        links.sort_unstable();
        for ((target, source), present) in links {
            w.u8(if *present {
                OP_PUT_LINK
            } else {
                OP_DELETE_LINK
            });
            w.bytes(target.as_bytes());
            w.bytes(source.as_bytes());
        }
        for head in &self.heads {
            w.u8(OP_PUT_HEAD);
            w.bytes(head.rid.as_bytes());
            w.bytes32(&head.encode()?)?;
        }
        Ok(())
    }
}

/// Content operations inside a [`Transaction`](crate::Transaction).
///
/// Returned by [`Transaction::content`](crate::Transaction::content).
pub struct ContentTx<'t, 'db> {
    pub(crate) staged: &'t mut ContentStaged<'db>,
}

impl fmt::Debug for ContentTx<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContentTx")
            .field("entities", &self.staged.heads.len())
            .finish()
    }
}

impl ContentTx<'_, '_> {
    /// The head of `rid` as this transaction sees it.
    fn head(&self, rid: Rid) -> Result<Head> {
        self.staged
            .note(entity_key(self.staged.engine.collection, rid));
        if let Some(head) = self.staged.heads.iter().find(|h| h.rid == rid) {
            return Ok(head.clone());
        }
        if self.staged.deleted.contains(&rid) {
            return Err(Error::invalid("entity", "no such entity"));
        }
        self.staged
            .engine
            .head(rid)?
            .ok_or_else(|| Error::invalid("entity", "no such entity"))
    }

    /// The working draft of `rid` in its own locale as this transaction
    /// sees it (its own changes included), or `None` when it does not
    /// exist. In [`commit_serializable`](crate::Database::commit_serializable),
    /// a change to the entity by another commit makes this one run again.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] or [`Error::Corrupt`] when the store cannot be read.
    pub fn draft(&self, rid: Rid) -> Result<Option<Entry>> {
        match self.head(rid) {
            Ok(head) => {
                let base = head.base();
                Ok(Some(head.entry(
                    base.locale,
                    head.last_revision,
                    base.draft.clone(),
                    None,
                )))
            }
            Err(Error::Invalid { .. }) => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// The space's types as this transaction sees them.
    fn types(&self) -> Types {
        self.staged.note(TYPES_CONFLICT_KEY.to_vec());
        match &self.staged.types {
            Some(types) => types.clone(),
            None => self.staged.engine.types(),
        }
    }

    fn put_head(&mut self, mut head: Head) -> Result<()> {
        let types = self.types();
        for variant in &head.variants {
            types.check(&head.kind, &variant.draft)?;
        }
        head.updated_ms = now_ms();
        head.status = match head.status {
            Status::Draft | Status::Review if head.is_published() => Status::Published,
            Status::Published if !head.is_published() => Status::Draft,
            status => status,
        };
        let refs = head.refs();
        let old = match self.staged.heads.iter().find(|h| h.rid == head.rid) {
            Some(prev) => prev.refs(),
            None => self.stored_refs(head.rid)?,
        };
        self.check_terms(&types, &head, &old)?;
        self.link(head.rid, &old, &refs)?;
        let key = entity_key(self.staged.engine.collection, head.rid);
        match self.staged.heads.iter_mut().find(|h| h.rid == head.rid) {
            Some(slot) => *slot = head,
            None => {
                self.staged.heads.push(head);
                self.staged.writes.push(key);
            }
        }
        Ok(())
    }

    /// Refuse a term added to a terms field that is not of the field's
    /// taxonomy. Terms already there (in `old`) are not read again.
    fn check_terms(&self, types: &Types, head: &Head, old: &[Rid]) -> Result<()> {
        for variant in &head.variants {
            for (name, value) in &variant.draft.fields {
                let Some(taxonomy) = types.taxonomy(&head.kind, name) else {
                    continue;
                };
                for term in value.refs().filter(|t| !old.contains(t)) {
                    self.staged
                        .note(entity_key(self.staged.engine.collection, term));
                    let kind = match self.staged.heads.iter().find(|h| h.rid == term) {
                        Some(h) => Some(h.kind.clone()),
                        None => self.staged.engine.head(term)?.map(|h| h.kind),
                    };
                    // A term that does not exist is refused by `link`.
                    if kind.is_some_and(|k| k != taxonomy) {
                        return Err(Error::invalid("field value", "a term of another taxonomy"));
                    }
                }
            }
        }
        Ok(())
    }

    /// The references of the stored head of `rid`, before this work
    /// rewrites it. A head stored by 0.1 to 0.3 is its own published body:
    /// that body is kept as the revision the rewritten head points at.
    fn stored_refs(&mut self, rid: Rid) -> Result<Vec<Rid>> {
        let engine = self.staged.engine;
        let Some(bytes) = engine.head_bytes_at(rid, engine.latest())? else {
            return Ok(Vec::new());
        };
        let stored = Head::decode(&bytes, 0)?;
        if Head::is_legacy(&bytes) {
            let base = stored.base();
            if let Some(published) = &base.published {
                let revision =
                    Revision::new(base.locale, stored.created_ms, "", base.draft.clone())?;
                self.staged.ops.push(StagedOp::Revision(
                    rid,
                    published.revision,
                    revision.encode()?,
                ));
                let _ = self
                    .staged
                    .revisions
                    .insert((rid, published.revision), (base.locale, base.draft.clone()));
            }
        }
        Ok(stored.refs())
    }

    /// Stage the change of `source`'s references from `old` to `new`. An
    /// added reference must name an entity that exists.
    fn link(&mut self, source: Rid, old: &[Rid], new: &[Rid]) -> Result<()> {
        for &target in new.iter().filter(|t| !old.contains(t)) {
            if target != source && !self.exists(target)? {
                return Err(Error::invalid("field value", "refers to no entity"));
            }
            self.staged.writes.push(link_conflict(target));
            let _ = self.staged.links.insert((target, source), true);
        }
        for &target in old.iter().filter(|t| !new.contains(t)) {
            let _ = self.staged.links.insert((target, source), false);
        }
        Ok(())
    }

    fn exists(&self, rid: Rid) -> Result<bool> {
        self.staged
            .note(entity_key(self.staged.engine.collection, rid));
        if self.staged.heads.iter().any(|h| h.rid == rid) {
            return Ok(true);
        }
        if self.staged.deleted.contains(&rid) {
            return Ok(false);
        }
        let engine = self.staged.engine;
        Ok(engine.head_bytes_at(rid, engine.latest())?.is_some())
    }

    /// The entities referring to `target` as this transaction sees it,
    /// other than `target` itself.
    fn referrers(&self, target: Rid) -> Result<Vec<Rid>> {
        self.staged.note(link_conflict(target));
        let mut out: Vec<Rid> = self
            .staged
            .engine
            .stored_referrers(target)?
            .into_iter()
            .filter(|s| self.staged.links.get(&(target, *s)) != Some(&false))
            .collect();
        for ((t, s), present) in &self.staged.links {
            if *t == target && *present && !out.contains(s) {
                out.push(*s);
            }
        }
        out.retain(|s| *s != target && !self.staged.deleted.contains(s));
        out.sort_unstable();
        Ok(out)
    }

    /// Refuse publishing `locales` of `head` when another entity's
    /// published value takes one of their unique values. The body each
    /// publishes is its draft; locales published before keep the keys they
    /// hold.
    fn claim_unique(&mut self, head: &Head, locales: &[Locale]) -> Result<()> {
        let types = self.types();
        let keys: Vec<Vec<u8>> = locales
            .iter()
            .filter_map(|l| head.variant(*l))
            .flat_map(|v| types.unique_keys(&head.kind, &v.draft))
            .collect();
        for key in keys {
            let holder = match self.staged.unique.get(&key) {
                Some(rid) => Some(*rid),
                None => self.staged.engine.type_index().holder(&key),
            };
            if holder.is_some_and(|r| r != head.rid) {
                return Err(Error::AlreadyExists {
                    what: "field value",
                });
            }
            self.staged.writes.push(key.clone());
            let _ = self.staged.unique.insert(key, head.rid);
        }
        Ok(())
    }

    /// Define `ty` in the space, or extend it: a redefinition keeps every
    /// field, kind, and flag it had.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the name or a field name breaks its rule, a
    /// field is declared twice, a redefinition drops something, the type
    /// becomes a singleton while it has more than one entity, or a new
    /// unique field already has a value two published entities share.
    pub fn define(&mut self, ty: Type) -> Result<()> {
        entity::check_name("type", &ty.name)?;
        for (name, _, _) in &ty.fields {
            entity::check_name("field name", name)?;
        }
        let engine = self.staged.engine;
        let next = self.types().with(ty.clone())?;
        if ty.singleton && engine.type_index().count(&ty.name).0 > 1 {
            return Err(Error::invalid("type", "has more than one entity"));
        }
        let mut seen = HashMap::new();
        for (head, legacy) in engine.all_heads()? {
            if !next.has_unique(&head.kind) {
                continue;
            }
            for variant in &head.variants {
                let Some(p) = &variant.published else {
                    continue;
                };
                let body = published_body(
                    &engine.store,
                    engine.collection,
                    &head,
                    legacy,
                    variant.locale,
                    p.revision,
                )?;
                for key in next.unique_keys(&head.kind, &body) {
                    if seen.insert(key, head.rid).is_some_and(|r| r != head.rid) {
                        return Err(Error::invalid(
                            "type",
                            "published entities share a value of a unique field",
                        ));
                    }
                }
            }
        }
        self.staged
            .ops
            .retain(|op| !matches!(op, StagedOp::Types(_)));
        self.staged.ops.push(StagedOp::Types(next.encode()?));
        self.staged.writes.push(TYPES_CONFLICT_KEY.to_vec());
        self.staged.types = Some(next);
        Ok(())
    }

    /// The route at `path` on `site` as this transaction sees it.
    fn route(&self, site: &str, path: &str) -> Option<RouteEntry> {
        self.staged.note(route_key(site, path));
        match self.staged.routes.get(&(site.to_owned(), path.to_owned())) {
            Some(entry) => *entry,
            None => self.staged.engine.routes.get(site, path),
        }
    }

    fn put_route(&mut self, site: &str, path: &str, entry: Option<RouteEntry>) {
        let _ = self
            .staged
            .routes
            .insert((site.to_owned(), path.to_owned()), entry);
        self.staged.writes.push(route_key(site, path));
        self.staged
            .ops
            .push(StagedOp::Route(site.to_owned(), path.to_owned(), entry));
    }

    /// Refuse `path` on `site` when another entity's page (or this
    /// entity's page in another locale) is there. Redirects and gone
    /// markers give way.
    fn check_free(&self, site: &str, path: &str, rid: Rid, locale: Locale) -> Result<()> {
        match self.route(site, path) {
            Some(RouteEntry {
                entity,
                kind: RouteKind::Page,
                locale: at,
                ..
            }) if entity != rid || at != locale => Err(Error::AlreadyExists { what: "path" }),
            _ => Ok(()),
        }
    }

    /// Serve `locale` of `head` at its published path, and leave the old
    /// published path, if it differs, as a 301 to the entity.
    fn route_published(&mut self, head: &Head, locale: Locale, old: Option<&str>) -> Result<()> {
        let Some(published) = head.variant(locale).and_then(|v| v.published.as_ref()) else {
            return Ok(());
        };
        let new = published.path.as_deref();
        if let Some(path) = new {
            self.check_free(&head.site, path, head.rid, locale)?;
            self.put_route(
                &head.site,
                path,
                Some(page(head, locale, published.revision)),
            );
        }
        if let Some(old) = old.filter(|old| Some(*old) != new) {
            let moved = RouteEntry {
                entity: head.rid,
                revision: published.revision,
                kind: RouteKind::Redirect {
                    to: head.rid,
                    status: MOVED,
                },
                visibility: head.visibility,
                locale,
            };
            self.put_route(&head.site, old, Some(moved));
        }
        Ok(())
    }

    /// The locale and body of revision `n` of `rid` as this transaction
    /// sees it.
    fn revision_body(&self, rid: Rid, n: u32) -> Result<Option<(Locale, Body)>> {
        if let Some(found) = self.staged.revisions.get(&(rid, n)) {
            return Ok(Some(found.clone()));
        }
        Ok(self
            .staged
            .engine
            .revision(rid, n)?
            .map(|r| (r.locale, r.body)))
    }

    fn record_revision(&mut self, head: &mut Head, locale: Locale, message: &str) -> Result<u32> {
        let draft = head
            .variant(locale)
            .ok_or_else(|| Error::invalid("locale", "the entity has no such translation"))?
            .draft
            .clone();
        self.record_body(head, locale, draft, message)
    }

    fn record_body(
        &mut self,
        head: &mut Head,
        locale: Locale,
        draft: Body,
        message: &str,
    ) -> Result<u32> {
        let n = head
            .last_revision
            .checked_add(1)
            .ok_or_else(|| Error::invalid("entity", "has too many revisions"))?;
        let revision = Revision::new(locale, now_ms(), message, draft.clone())?;
        self.staged
            .ops
            .push(StagedOp::Revision(head.rid, n, revision.encode()?));
        let _ = self.staged.revisions.insert((head.rid, n), (locale, draft));
        head.last_revision = n;
        Ok(n)
    }

    /// Create `entity` as a draft and return its record id. Nothing is
    /// published, so neither [`Content::get`] nor [`Content::resolve`] finds
    /// it until [`publish`](Self::publish).
    ///
    /// ```no_run
    /// # fn main() -> nex_db::Result<()> {
    /// use nex_db::Entity;
    /// let db = nex_db::open("data/site")?;
    /// let rid = db.commit(|tx| {
    ///     let rid =
    ///         tx.content().create(Entity::new("page").field("title", "Hello").path("/hello"))?;
    ///     tx.content().publish(rid)?;
    ///     Ok(rid)
    /// })?;
    /// # let _ = rid;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] (`what = "path"`) when another entity is
    ///   served at the path on its site.
    /// - [`Error::Invalid`] when a name, path, site, or value breaks its rule.
    pub fn create(&mut self, entity: Entity) -> Result<Rid> {
        let rid = Rid::generate();
        let engine = self.staged.engine;
        if self
            .types()
            .get(entity.kind_name())
            .is_some_and(|t| t.singleton)
        {
            let staged = self
                .staged
                .heads
                .iter()
                .any(|h| h.kind == entity.kind_name());
            if staged || engine.type_index().count(entity.kind_name()).0 > 0 {
                return Err(Error::AlreadyExists { what: "singleton" });
            }
            self.staged
                .writes
                .push(format!("k{}", entity.kind_name()).into_bytes());
        }
        self.staged.note(SPACE_CONFLICT_KEY.to_vec());
        let default = engine.space().default_locale;
        let head = entity.into_head(rid, now_ms(), default)?;
        if let Some(parent) = head.parent {
            let _ = self.check_parent(rid, parent)?;
        }
        let base = head.base();
        if let Some(path) = base.draft.path.as_deref() {
            self.check_free(&head.site, path, rid, base.locale)?;
        }
        self.put_head(head)?;
        Ok(rid)
    }

    /// Change the working draft of the entity's own locale. Records no
    /// revision.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the entity does not exist or the result
    /// breaks a rule of [`create`](Self::create).
    pub fn save_draft(&mut self, rid: Rid, patch: Patch) -> Result<()> {
        let mut head = self.head(rid)?;
        let locale = head.base().locale;
        self.patch_variant(&mut head, locale, patch)?;
        self.put_head(head)?;
        Ok(())
    }

    fn patch_variant(&self, head: &mut Head, locale: Locale, patch: Patch) -> Result<()> {
        let variant = head
            .variant_mut(locale)
            .ok_or_else(|| Error::invalid("locale", "the entity has no such translation"))?;
        patch.apply(&mut variant.draft)
    }

    /// Change the draft of the `locale` translation, starting it when there
    /// is none: a new translation starts from the fields of the entity's
    /// own draft, without a path. Each call records the revision its own
    /// locale publishes as the one the translation was made from, so it
    /// leaves [`Listing::outdated`].
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the entity does not exist, has 64 locales,
    /// or the result breaks a rule of [`create`](Self::create).
    pub fn translate(&mut self, rid: Rid, locale: Locale, patch: Patch) -> Result<()> {
        let mut head = self.head(rid)?;
        let source = head.base().published.as_ref().map_or(0, |p| p.revision);
        match head.variant_mut(locale) {
            Some(variant) => variant.source = source,
            None => {
                let draft = Body {
                    path: None,
                    fields: head.base().draft.fields.clone(),
                };
                head.add_variant(locale, draft, source)?;
            }
        }
        self.patch_variant(&mut head, locale, patch)?;
        self.put_head(head)?;
        Ok(())
    }

    /// Record the working draft of the entity's own locale as a fixed
    /// revision with `message` (at most 1,024 bytes) and return its number.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the entity does not exist or the message is
    /// too long.
    pub fn save_revision(&mut self, rid: Rid, message: &str) -> Result<u32> {
        let mut head = self.head(rid)?;
        let locale = head.base().locale;
        let n = self.record_revision(&mut head, locale, message)?;
        self.put_head(head)?;
        Ok(n)
    }

    /// Publish the working draft of the entity's own locale. See
    /// [`publish_in`](Self::publish_in).
    ///
    /// # Errors
    ///
    /// As [`publish_in`](Self::publish_in).
    pub fn publish(&mut self, rid: Rid) -> Result<u32> {
        let locale = self.head(rid)?.base().locale;
        self.publish_in(rid, &[locale])
    }

    /// Publish the working drafts of `locales` and return the newest
    /// revision published. A locale whose draft has not changed since its
    /// published revision keeps that revision; otherwise a new one is
    /// recorded. Each locale is then served at its draft's path; a
    /// different path it was published at before becomes a 301 to it.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] (`what = "path"`) when another page is
    ///   served at a path.
    /// - [`Error::Invalid`] when the entity does not exist, is trashed, or
    ///   has no translation for a locale.
    pub fn publish_in(&mut self, rid: Rid, locales: &[Locale]) -> Result<u32> {
        let mut head = self.head(rid)?;
        if head.status == Status::Trashed {
            return Err(Error::invalid("entity", "is in the trash"));
        }
        let mut newest = 0;
        for &locale in locales {
            let variant = head
                .variant(locale)
                .ok_or_else(|| Error::invalid("locale", "the entity has no such translation"))?;
            // The newest revision of the entity if it is this locale's,
            // then the published one: either is kept when the draft has not
            // changed since.
            let mut keep = None;
            let candidates = [
                Some(head.last_revision).filter(|n| *n > 0),
                variant.published.as_ref().map(|p| p.revision),
            ];
            for n in candidates.into_iter().flatten() {
                if let Some((l, body)) = self.revision_body(rid, n)? {
                    if l == locale && body == variant.draft {
                        keep = Some(n);
                        break;
                    }
                }
            }
            let n = match keep {
                Some(n) => n,
                None => self.record_revision(&mut head, locale, "")?,
            };
            let now = self.staged.engine.publish_ms();
            let Some(variant) = head.variant_mut(locale) else {
                continue;
            };
            let old = variant.published.take().and_then(|p| p.path);
            variant.published = Some(Published {
                revision: n,
                at_ms: now,
                path: variant.draft.path.clone(),
                refs: ref_set(variant.draft.refs()),
            });
            if head.first_published_ms == 0 {
                head.first_published_ms = now;
            }
            head.status = Status::Published;
            self.route_published(&head, locale, old.as_deref())?;
            newest = newest.max(n);
        }
        self.claim_unique(&head, locales)?;
        self.put_head(head)?;
        Ok(newest)
    }

    /// Stop serving the entity in every locale. See
    /// [`unpublish_in`](Self::unpublish_in).
    ///
    /// # Errors
    ///
    /// As [`unpublish_in`](Self::unpublish_in).
    pub fn unpublish(&mut self, rid: Rid) -> Result<bool> {
        let locales: Vec<Locale> = self.head(rid)?.variants.iter().map(|v| v.locale).collect();
        self.unpublish_in(rid, &locales)
    }

    /// Stop serving `locales` of the entity: their paths no longer resolve
    /// and readers fall back to other locales. Drafts and revisions stay.
    /// When no locale is left published the status becomes
    /// [`Status::Draft`]. Returns `false` when none of them was published.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the entity does not exist.
    pub fn unpublish_in(&mut self, rid: Rid, locales: &[Locale]) -> Result<bool> {
        let mut head = self.head(rid)?;
        let site = head.site.clone();
        let mut any = false;
        for &locale in locales {
            let Some(published) = head.variant_mut(locale).and_then(|v| v.published.take()) else {
                continue;
            };
            any = true;
            if let Some(path) = published.path {
                self.put_route(&site, &path, None);
            }
        }
        if any {
            self.put_head(head)?;
        }
        Ok(any)
    }

    /// Serve the entity's own locale at `path`. See
    /// [`set_path_in`](Self::set_path_in).
    ///
    /// # Errors
    ///
    /// As [`set_path_in`](Self::set_path_in).
    pub fn set_path(&mut self, rid: Rid, path: &str) -> Result<()> {
        let locale = self.head(rid)?.base().locale;
        self.set_path_in(rid, locale, path)
    }

    /// Serve `locale` of the entity at `path` from now on: its draft's path
    /// changes, and when it is published, it moves at once and its old path
    /// becomes a 301 to it.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] (`what = "path"`) when another page is
    ///   served at the path.
    /// - [`Error::Invalid`] when the entity does not exist, has no such
    ///   translation, or the path breaks its rule.
    pub fn set_path_in(&mut self, rid: Rid, locale: Locale, path: &str) -> Result<()> {
        let mut head = self.head(rid)?;
        self.patch_variant(&mut head, locale, Patch::new().path(path))?;
        self.check_free(&head.site, path, rid, locale)?;
        let old = head
            .variant_mut(locale)
            .and_then(|v| v.published.as_mut())
            .map(|p| p.path.replace(path.to_owned()));
        if let Some(old) = old {
            self.route_published(&head, locale, old.as_deref())?;
        }
        self.put_head(head)?;
        Ok(())
    }

    /// Set the entity's status to `status`: [`Status::Draft`] or
    /// [`Status::Review`] for an unpublished entity, or
    /// [`Status::Archived`], which also unpublishes every locale.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the entity does not exist, for
    /// [`Status::Published`] (use [`publish`](Self::publish)) and
    /// [`Status::Trashed`], and for `Draft` or `Review` while published.
    pub fn set_status(&mut self, rid: Rid, status: Status) -> Result<()> {
        match status {
            Status::Archived => {
                let _ = self.unpublish(rid)?;
            }
            Status::Draft | Status::Review => {
                if self.head(rid)?.is_published() {
                    return Err(Error::invalid("status", "unpublish the entity first"));
                }
            }
            Status::Published | Status::Trashed => {
                return Err(Error::invalid(
                    "status",
                    "set by publish and trash, not set_status",
                ));
            }
        }
        let mut head = self.head(rid)?;
        head.status = status;
        self.put_head(head)?;
        Ok(())
    }

    /// Set who may see the entity. The routes of its published locales
    /// carry the change at once.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the entity does not exist.
    pub fn set_visibility(&mut self, rid: Rid, visibility: Visibility) -> Result<()> {
        let mut head = self.head(rid)?;
        head.visibility = visibility;
        let site = head.site.clone();
        let routes: Vec<(String, RouteEntry)> = head
            .variants
            .iter()
            .filter_map(|v| {
                let p = v.published.as_ref()?;
                Some((p.path.clone()?, page(&head, v.locale, p.revision)))
            })
            .collect();
        for (path, entry) in routes {
            self.put_route(&site, &path, Some(entry));
        }
        self.put_head(head)?;
        Ok(())
    }

    /// Take the entity off the site: every path it is published at answers
    /// [`RouteKind::Gone`] (410), readers no longer find it, and its status
    /// becomes [`Status::Trashed`]. Drafts and revisions stay, so
    /// [`restore`](Self::restore) can bring it back.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the entity does not exist or is already in
    /// the trash.
    pub fn trash(&mut self, rid: Rid) -> Result<()> {
        let mut head = self.head(rid)?;
        if head.status == Status::Trashed {
            return Err(Error::invalid("entity", "is in the trash"));
        }
        let site = head.site.clone();
        let mut gone = Vec::new();
        for variant in &mut head.variants {
            if let Some(path) = variant.published.take().and_then(|p| p.path) {
                gone.push((variant.locale, path));
            }
        }
        for (locale, path) in &gone {
            let entry = RouteEntry {
                entity: rid,
                revision: 0,
                kind: RouteKind::Gone,
                visibility: head.visibility,
                locale: *locale,
            };
            self.put_route(&site, path, Some(entry));
        }
        head.gone.extend(gone);
        head.status = Status::Trashed;
        for variant in &mut head.variants {
            variant.schedule = None;
        }
        self.put_head(head)
    }

    /// Bring a trashed entity back as a draft. The paths its trash left
    /// gone are free again (until it is published).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the entity does not exist or is not in the
    /// trash.
    pub fn restore(&mut self, rid: Rid) -> Result<()> {
        let mut head = self.head(rid)?;
        if head.status != Status::Trashed {
            return Err(Error::invalid("entity", "is not in the trash"));
        }
        let site = head.site.clone();
        for (_, path) in std::mem::take(&mut head.gone) {
            let ours = matches!(
                self.route(&site, &path),
                Some(RouteEntry { entity, kind: RouteKind::Gone, .. }) if entity == rid
            );
            if ours {
                self.put_route(&site, &path, None);
            }
        }
        head.status = Status::Draft;
        self.put_head(head)
    }

    /// Remove the entity and its revisions for good. The paths it is
    /// published at, and those its trash left gone, answer
    /// [`RouteKind::Gone`] (410) until another entity takes them.
    ///
    /// Each entity referring to it is handled by the rule of its referring
    /// field ([`Type::reference`]): [`Rule::Restrict`] (also the rule of a
    /// field none is declared for) refuses the delete, [`Rule::Detach`]
    /// removes the field, and [`Rule::Cascade`] deletes that entity too,
    /// by the same rules. A field in a published body is detached by
    /// publishing a new revision without it.
    ///
    /// # Errors
    ///
    /// - [`Error::Restricted`] when a reference rule keeps the entity (or
    ///   one it cascades to).
    /// - [`Error::Invalid`] when the entity does not exist or the delete
    ///   cascades to more than 1,000 entities.
    pub fn delete(&mut self, rid: Rid) -> Result<()> {
        let _ = self.head(rid)?;
        // Plan first, so a refusal stages nothing.
        let types = self.types();
        let mut doomed = vec![rid];
        let mut seen: HashSet<Rid> = doomed.iter().copied().collect();
        let mut detach = Vec::new();
        let mut stale = Vec::new();
        let mut next = 0;
        while let Some(&target) = doomed.get(next) {
            next += 1;
            for source in self.referrers(target)? {
                if seen.contains(&source) {
                    continue;
                }
                let head = self.head(source)?;
                match self.rule_for(&types, &head, target)? {
                    None => stale.push((target, source)),
                    Some(Rule::Cascade) => {
                        if doomed.len() >= MAX_CASCADE {
                            return Err(Error::invalid(
                                "delete",
                                "cascades to more than 1,000 entities",
                            ));
                        }
                        let _ = seen.insert(source);
                        doomed.push(source);
                    }
                    Some(Rule::Detach) => detach.push((source, target)),
                    Some(_) => return Err(Error::Restricted { what: "entity" }),
                }
            }
        }
        // A reference record no field backs (left by a format before) is
        // dropped.
        for key in stale {
            let _ = self.staged.links.insert(key, false);
        }
        for (source, target) in detach {
            if !seen.contains(&source) {
                self.detach(source, target)?;
            }
        }
        for rid in doomed {
            self.remove(rid)?;
        }
        Ok(())
    }

    /// The strongest rule of the fields of `head` that refer to `target`:
    /// restrict, then cascade, then detach. `None` when no field does.
    fn rule_for(&self, types: &Types, head: &Head, target: Rid) -> Result<Option<Rule>> {
        // A parent keeps its children: move or delete them first.
        if head.parent == Some(target) {
            return Ok(Some(Rule::Restrict));
        }
        let mut names: Vec<String> = Vec::new();
        for variant in &head.variants {
            names.extend(variant.draft.fields_referring(target).map(str::to_owned));
            let Some(published) = &variant.published else {
                continue;
            };
            if !published.refs.contains(&target) {
                continue;
            }
            if let Some((_, body)) = self.revision_body(head.rid, published.revision)? {
                names.extend(body.fields_referring(target).map(str::to_owned));
            }
        }
        let rank = |rule: Rule| match rule {
            Rule::Detach => 0,
            Rule::Cascade => 1,
            _ => 2,
        };
        Ok(names
            .iter()
            .map(|name| types.rule(&head.kind, name))
            .max_by_key(|rule| rank(*rule)))
    }

    /// Remove every field of `source` that refers to `target`: from its
    /// drafts, and from each published body by publishing a new revision
    /// without it.
    fn detach(&mut self, source: Rid, target: Rid) -> Result<()> {
        let mut head = self.head(source)?;
        let before = head.clone();
        for variant in &mut head.variants {
            let _ = variant.draft.detach(target);
        }
        let published: Vec<(Locale, u32)> = head
            .variants
            .iter()
            .filter_map(|v| {
                let p = v.published.as_ref().filter(|p| p.refs.contains(&target))?;
                Some((v.locale, p.revision))
            })
            .collect();
        for (locale, n) in published {
            let mut body = match self.revision_body(source, n)? {
                Some((_, body)) => body,
                // A head from 0.1 to 0.3: its draft was its published body.
                None => before
                    .variant(locale)
                    .map(|v| v.draft.clone())
                    .ok_or_else(|| Error::corrupt("an entity without its revision", 0))?,
            };
            let _ = body.detach(target);
            let refs = ref_set(body.refs());
            let n = self.record_body(&mut head, locale, body, "")?;
            if let Some(p) = head.variant_mut(locale).and_then(|v| v.published.as_mut()) {
                p.revision = n;
                p.at_ms = self.staged.engine.publish_ms();
                p.refs = refs;
            }
            self.route_published(&head, locale, None)?;
        }
        self.put_head(head)
    }

    /// Delete `rid` itself: trash it, then remove it and its references.
    fn remove(&mut self, rid: Rid) -> Result<()> {
        let head = self.head(rid)?;
        if head.status != Status::Trashed {
            self.trash(rid)?;
        }
        let refs = match self.staged.heads.iter().find(|h| h.rid == rid) {
            Some(head) => head.refs(),
            None => self.stored_refs(rid)?,
        };
        for target in refs {
            let _ = self.staged.links.insert((target, rid), false);
        }
        self.staged.heads.retain(|h| h.rid != rid);
        let _ = self.staged.deleted.insert(rid);
        self.staged.ops.push(StagedOp::Delete(rid));
        self.staged
            .writes
            .push(entity_key(self.staged.engine.collection, rid));
        self.staged.writes.push(link_conflict(rid));
        Ok(())
    }

    /// Walk up from `parent`: refuse it when `rid` is among its ancestors
    /// (a cycle) or the tree would be deeper than 64. Returns `parent` and
    /// its ancestors.
    fn check_parent(&self, rid: Rid, parent: Rid) -> Result<Vec<Rid>> {
        let mut line = Vec::new();
        let mut at = Some(parent);
        while let Some(p) = at {
            if p == rid {
                return Err(Error::invalid("parent", "would make a cycle"));
            }
            if line.len() >= MAX_DEPTH {
                return Err(Error::invalid("parent", "the tree is deeper than 64"));
            }
            line.push(p);
            at = self.head(p)?.parent;
        }
        Ok(line)
    }

    /// Place the entity under `parent` in the page tree, or at its root
    /// with `None`. Takes effect at once, published or not.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the entity or the parent does not exist, the
    /// parent is the entity or one of its descendants, or the tree would be
    /// deeper than 64.
    pub fn set_parent(&mut self, rid: Rid, parent: Option<Rid>) -> Result<()> {
        let mut head = self.head(rid)?;
        if let Some(parent) = parent {
            let line = self.check_parent(rid, parent)?;
            self.staged
                .writes
                .extend(line.into_iter().map(tree_conflict));
        }
        self.staged.writes.push(tree_conflict(rid));
        head.parent = parent;
        self.put_head(head)
    }

    /// Set the entity's place among its parent's children, lowest first.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the entity does not exist.
    pub fn set_order(&mut self, rid: Rid, order: i64) -> Result<()> {
        let mut head = self.head(rid)?;
        head.order = order;
        self.put_head(head)
    }

    /// Mark the entity sticky or not ([`Entity::sticky`]). Takes effect at
    /// once, published or not.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the entity does not exist.
    pub fn set_sticky(&mut self, rid: Rid, sticky: bool) -> Result<()> {
        let mut head = self.head(rid)?;
        head.sticky = sticky;
        self.put_head(head)
    }

    /// Redirect `from` on `site` to the entity `to` with `status` (301,
    /// 302, 307, or 308): [`Content::resolve`] answers
    /// [`RouteKind::Redirect`], and the entity's current path is
    /// `get(to)?.route()`. Replaces a redirect or a gone marker at `from`.
    /// A redirect stays when its target is deleted; remove it with
    /// [`remove_route`](Self::remove_route).
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] (`what = "path"`) when an entity is
    ///   served at `from`.
    /// - [`Error::Invalid`] when the site, the path, or the status breaks
    ///   its rule, or `to` names no entity.
    pub fn add_redirect(&mut self, site: &str, from: &str, to: Rid, status: u16) -> Result<()> {
        entity::check_site(site)?;
        entity::check_path(from)?;
        if !matches!(status, 301 | 302 | 307 | 308) {
            return Err(Error::invalid("status", "must be 301, 302, 307, or 308"));
        }
        let target = self.head(to)?;
        if let Some(RouteEntry {
            kind: RouteKind::Page,
            ..
        }) = self.route(site, from)
        {
            return Err(Error::AlreadyExists { what: "path" });
        }
        let entry = RouteEntry {
            entity: to,
            revision: target.base().published.as_ref().map_or(0, |p| p.revision),
            kind: RouteKind::Redirect { to, status },
            visibility: target.visibility,
            locale: target.base().locale,
        };
        self.put_route(site, from, Some(entry));
        Ok(())
    }

    /// Remove the redirect or gone marker at `path` on `site`, so the path
    /// resolves to nothing. Returns `false` when there is none.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when an entity is served at `path`: unpublish it
    /// or give it another path instead.
    pub fn remove_route(&mut self, site: &str, path: &str) -> Result<bool> {
        match self.route(site, path) {
            None => Ok(false),
            Some(RouteEntry {
                kind: RouteKind::Page,
                ..
            }) => Err(Error::invalid("path", "an entity is served there")),
            Some(_) => {
                self.put_route(site, path, None);
                Ok(true)
            }
        }
    }

    /// Replace the entity's authors, in order (at most 16; a repeat counts
    /// once). Takes effect at once, published or not.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the entity does not exist or there are more
    /// than 16 authors.
    pub fn set_authors(&mut self, rid: Rid, authors: &[AccountId]) -> Result<()> {
        let mut head = self.head(rid)?;
        let mut list = Vec::with_capacity(authors.len());
        for author in authors {
            if !list.contains(author) {
                list.push(*author);
            }
        }
        if list.len() > entity::MAX_AUTHORS {
            return Err(Error::invalid("authors", "at most 16"));
        }
        head.authors = list;
        self.put_head(head)
    }

    /// Schedule `action` for the entity's own locale at `at`. See
    /// [`schedule_in`](Self::schedule_in).
    ///
    /// # Errors
    ///
    /// As [`schedule_in`](Self::schedule_in).
    pub fn schedule(&mut self, rid: Rid, action: Action, at: SystemTime) -> Result<()> {
        let locale = self.head(rid)?.base().locale;
        self.schedule_in(rid, locale, action, at)
    }

    /// Schedule `action` for `locale` of the entity at `at`: the database
    /// publishes the locale's working draft as it is then
    /// ([`publish_in`](Self::publish_in)), or unpublishes it, in a commit of
    /// its own, within moments of `at` (at once for a time already past).
    /// One schedule per locale: a new one replaces it. A schedule that
    /// cannot run (the path is taken by then) is dropped and reported to
    /// the observer ([`Observer::on_error`](crate::Observer::on_error)).
    /// Trashing the entity drops its schedules.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the entity does not exist, is in the trash,
    /// has no such translation, or `at` is before 1970.
    pub fn schedule_in(
        &mut self,
        rid: Rid,
        locale: Locale,
        action: Action,
        at: SystemTime,
    ) -> Result<()> {
        let at_ms = at
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .map_err(|_| Error::invalid("time", "before 1970"))?;
        let mut head = self.head(rid)?;
        if head.status == Status::Trashed {
            return Err(Error::invalid("entity", "is in the trash"));
        }
        head.variant_mut(locale)
            .ok_or_else(|| Error::invalid("locale", "the entity has no such translation"))?
            .schedule = Some((action, at_ms));
        self.put_head(head)
    }

    /// Drop the schedule of the entity's own locale. See
    /// [`cancel_schedule_in`](Self::cancel_schedule_in).
    ///
    /// # Errors
    ///
    /// As [`cancel_schedule_in`](Self::cancel_schedule_in).
    pub fn cancel_schedule(&mut self, rid: Rid) -> Result<bool> {
        let locale = self.head(rid)?.base().locale;
        self.cancel_schedule_in(rid, locale)
    }

    /// Drop the schedule of `locale`; `false` when it had none.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the entity does not exist.
    pub fn cancel_schedule_in(&mut self, rid: Rid, locale: Locale) -> Result<bool> {
        let mut head = self.head(rid)?;
        let Some(variant) = head.variant_mut(locale) else {
            return Ok(false);
        };
        if variant.schedule.take().is_none() {
            return Ok(false);
        }
        self.put_head(head)?;
        Ok(true)
    }

    /// Run the schedule `action` at `at` of `locale` of `rid`, if it is
    /// still there: drop it, then publish or unpublish.
    pub(crate) fn fire(&mut self, rid: Rid, locale: Locale, action: Action, at: u64) -> Result<()> {
        if !self.clear_schedule(rid, locale, action, at)? {
            return Ok(());
        }
        match action {
            Action::Publish => {
                let _ = self.publish_in(rid, &[locale])?;
            }
            Action::Unpublish => {
                let _ = self.unpublish_in(rid, &[locale])?;
            }
        }
        Ok(())
    }

    /// Drop the schedule `action` at `at` of `locale` of `rid`, if it is
    /// still there; true when it was.
    pub(crate) fn clear_schedule(
        &mut self,
        rid: Rid,
        locale: Locale,
        action: Action,
        at: u64,
    ) -> Result<bool> {
        let Ok(mut head) = self.head(rid) else {
            return Ok(false);
        };
        let Some(variant) = head.variant_mut(locale) else {
            return Ok(false);
        };
        if variant.schedule != Some((action, at)) {
            return Ok(false);
        }
        variant.schedule = None;
        self.put_head(head)?;
        Ok(true)
    }

    /// Replace the space's settings: its default locale and fallback
    /// chains. Entities keep the locales they were written in; readers who
    /// ask for no locale get the new default.
    pub fn set_space(&mut self, spec: SpaceSpec) {
        self.staged
            .ops
            .retain(|op| !matches!(op, StagedOp::Space(_)));
        self.staged.ops.push(StagedOp::Space(spec.encode()));
        self.staged.writes.push(SPACE_CONFLICT_KEY.to_vec());
    }
}

/// The content engine's operations outside a transaction.
///
/// Returned by [`Database::content`].
#[derive(Debug, Clone, Copy)]
pub struct Content<'db> {
    pub(crate) db: &'db Database,
    pub(crate) engine: &'db ContentEngine,
}

impl Content<'_> {
    fn engine(&self) -> &ContentEngine {
        self.engine
    }

    /// The space this handle acts on.
    pub(crate) fn collection(&self) -> u32 {
        self.engine.collection
    }

    /// The published revision of `rid`, or `None` when nothing is
    /// published (or the entity does not exist).
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] when the store cannot be read, [`Error::Corrupt`]
    /// when a stored record fails its checks.
    pub fn get(&self, rid: Rid) -> Result<Option<Entry>> {
        self.engine().published_in(rid, None, self.db.visible())
    }

    /// The published revision of `rid` in `locale`, else along the space's
    /// fallback chain for it, else in the entity's own locale;
    /// [`Entry::fallback`] says when another locale was served.
    ///
    /// # Errors
    ///
    /// As [`get`](Self::get).
    pub fn get_in(&self, rid: Rid, locale: Locale) -> Result<Option<Entry>> {
        self.engine()
            .published_in(rid, Some(locale), self.db.visible())
    }

    /// The working draft of `rid` in `locale`, or `None` when it has no
    /// such translation.
    ///
    /// # Errors
    ///
    /// As [`get`](Self::get).
    pub fn draft_in(&self, rid: Rid, locale: Locale) -> Result<Option<Entry>> {
        self.engine().draft_in(rid, Some(locale), self.db.visible())
    }

    /// Define or extend a type in its own commit. See
    /// [`ContentTx::define`].
    ///
    /// ```
    /// # #[cfg(feature = "content")]
    /// # fn main() -> nex_db::Result<()> {
    /// # let dir = std::env::temp_dir().join(format!("nex-db-define-doc-{}", std::process::id()));
    /// # let _ = std::fs::remove_dir_all(&dir);
    /// use nex_db::{Entity, FieldType, Type};
    /// let db = nex_db::open(&dir)?;
    /// db.content().define(Type::new("post").field("words", FieldType::Int))?;
    /// assert!(db.content().create(Entity::new("post").field("words", "many")).is_err());
    /// # drop(db);
    /// # std::fs::remove_dir_all(&dir).unwrap();
    /// # Ok(())
    /// # }
    /// # #[cfg(not(feature = "content"))]
    /// # fn main() {}
    /// ```
    ///
    /// # Errors
    ///
    /// As [`ContentTx::define`], plus the errors of [`Database::commit`].
    pub fn define(&self, ty: Type) -> Result<()> {
        self.db
            .commit(|tx| tx.content_of(self.engine.collection).define(ty.clone()))
    }

    /// The type named `name`, if the space defines it.
    #[must_use]
    pub fn type_named(&self, name: &str) -> Option<Type> {
        self.engine().types().get(name).cloned()
    }

    /// The space's settings.
    pub fn space(&self) -> SpaceSpec {
        self.engine().space()
    }

    /// Replace the space's settings in their own commit. See
    /// [`ContentTx::set_space`].
    ///
    /// # Errors
    ///
    /// The errors of [`Database::commit`].
    pub fn set_space(&self, spec: SpaceSpec) -> Result<()> {
        self.db.commit(|tx| {
            tx.content_of(self.engine.collection)
                .set_space(spec.clone());
            Ok(())
        })
    }

    /// The working draft of `rid`, for editors, or `None` when the entity
    /// does not exist.
    ///
    /// # Errors
    ///
    /// As [`get`](Self::get).
    pub fn draft(&self, rid: Rid) -> Result<Option<Entry>> {
        self.engine().draft_in(rid, None, self.db.visible())
    }

    /// Every revision of `rid`, oldest first.
    ///
    /// # Errors
    ///
    /// As [`get`](Self::get).
    pub fn revisions(&self, rid: Rid) -> Result<Vec<RevisionInfo>> {
        self.engine().revisions(rid)
    }

    /// Revision `n` of `rid` as it was recorded, or `None`.
    ///
    /// # Errors
    ///
    /// As [`get`](Self::get).
    pub fn revision(&self, rid: Rid, n: u32) -> Result<Option<Entry>> {
        let engine = self.engine();
        let Some(head) = engine.head(rid)? else {
            return Ok(None);
        };
        Ok(engine
            .revision(rid, n)?
            .map(|r| head.entry(r.locale, n, r.body, None)))
    }

    /// The route at `path` on `site`, or `None`. Only published entities
    /// are routed. Reads memory only and allocates nothing.
    ///
    /// ```no_run
    /// # fn main() -> nex_db::Result<()> {
    /// use nex_db::RouteKind;
    /// let db = nex_db::open("data/site")?;
    /// match db.content().resolve("example.com", "/u/ann")? {
    ///     Some(route) if route.kind() == RouteKind::Page => {
    ///         let page = db.content().get(route.entity())?;
    ///         # let _ = page;
    ///     }
    ///     _ => {}
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// None in this version; the `Result` leaves room for routes that are
    /// not held in memory.
    pub fn resolve(&self, site: &str, path: &str) -> Result<Option<RouteEntry>> {
        Ok(self.engine().routes.get(site, path))
    }

    /// The first page of `listing`: published entities only, read from an
    /// index, never by scanning.
    ///
    /// ```no_run
    /// # fn main() -> nex_db::Result<()> {
    /// use nex_db::Listing;
    /// let db = nex_db::open("data/site")?;
    /// let page = db.content().list(&Listing::latest("post").site("example.com").limit(10))?;
    /// for post in page.items() {
    ///     # let _ = post;
    /// }
    /// if let Some(more) = page.next() {
    ///     let older = db.content().next_page(more)?;
    ///     # let _ = older;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// As [`get`](Self::get).
    pub fn list(&self, listing: &Listing) -> Result<Page<Entry>> {
        self.page(listing, None)
    }

    /// The page after `cursor`.
    ///
    /// # Errors
    ///
    /// As [`get`](Self::get).
    pub fn next_page(&self, cursor: &Cursor) -> Result<Page<Entry>> {
        self.page(&cursor.listing, Some(cursor.after))
    }

    fn page(&self, listing: &Listing, after: Option<(u64, [u8; 16])>) -> Result<Page<Entry>> {
        let engine = self.engine();
        let (ids, last) = engine.lists.page(listing, after);
        let mut items = Vec::with_capacity(ids.len());
        let at = self.db.visible();
        for rid in ids {
            // Unpublished (or deleted) since the index was read: left out.
            let entry = match listing.filter {
                Some(lists::Filter::Outdated(locale)) => engine
                    .draft_in(rid, Some(locale), at)?
                    .filter(|e| e.locale() == locale),
                _ => engine.published_in(rid, None, at)?,
            };
            if let Some(entry) = entry {
                items.push(entry);
            }
        }
        Ok(Page {
            items,
            next: last.map(|after| Cursor {
                listing: listing.clone(),
                after,
            }),
        })
    }

    /// Every entry of `listing`, page by page, for sitemaps and feeds. Each
    /// page is read when the one before it runs out; an entity published
    /// meanwhile may be missed or, when it moves, seen twice.
    ///
    /// ```no_run
    /// # fn main() -> nex_db::Result<()> {
    /// use nex_db::Listing;
    /// let db = nex_db::open("data/site")?;
    /// for entry in db.content().stream(Listing::latest("post").limit(1000)) {
    ///     let entry = entry?;
    ///     # let _ = entry;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn stream(&self, listing: Listing) -> Stream<'_> {
        Stream {
            content: *self,
            listing,
            after: None,
            buffer: std::collections::VecDeque::new(),
            done: false,
        }
    }

    /// The published revisions of `rids` in `locale` (as
    /// [`get_in`](Self::get_in)), all read at one snapshot, in order;
    /// `None` where nothing is published.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for more than 1,000 ids, and the errors of
    /// [`get`](Self::get).
    pub fn get_many(&self, rids: &[Rid], locale: Locale) -> Result<Vec<Option<Entry>>> {
        if rids.len() > lists::MAX_PAGE {
            return Err(Error::invalid("ids", "at most 1,000"));
        }
        let snapshot = self.db.snapshot();
        let at = snapshot.seq();
        rids.iter()
            .map(|rid| self.engine().published_in(*rid, Some(locale), at))
            .collect()
    }

    /// Mark an entity sticky or not in its own commit. See
    /// [`ContentTx::set_sticky`].
    ///
    /// # Errors
    ///
    /// As [`ContentTx::set_sticky`], plus the errors of
    /// [`Database::commit`].
    pub fn set_sticky(&self, rid: Rid, sticky: bool) -> Result<()> {
        self.db.commit(|tx| {
            tx.content_of(self.engine.collection)
                .set_sticky(rid, sticky)
        })
    }

    /// Add a redirect in its own commit. See [`ContentTx::add_redirect`].
    ///
    /// # Errors
    ///
    /// As [`ContentTx::add_redirect`], plus the errors of
    /// [`Database::commit`].
    pub fn add_redirect(&self, site: &str, from: &str, to: Rid, status: u16) -> Result<()> {
        self.db.commit(|tx| {
            tx.content_of(self.engine.collection)
                .add_redirect(site, from, to, status)
        })
    }

    /// Remove a redirect or gone marker in its own commit. See
    /// [`ContentTx::remove_route`].
    ///
    /// # Errors
    ///
    /// As [`ContentTx::remove_route`], plus the errors of
    /// [`Database::commit`].
    pub fn remove_route(&self, site: &str, path: &str) -> Result<bool> {
        self.db.commit(|tx| {
            tx.content_of(self.engine.collection)
                .remove_route(site, path)
        })
    }

    /// Create an entity in its own commit. See [`ContentTx::create`].
    ///
    /// # Errors
    ///
    /// As [`ContentTx::create`], plus the errors of [`Database::commit`].
    pub fn create(&self, entity: Entity) -> Result<Rid> {
        self.db
            .commit(|tx| tx.content_of(self.engine.collection).create(entity.clone()))
    }

    /// Change a draft in its own commit. See [`ContentTx::save_draft`].
    ///
    /// # Errors
    ///
    /// As [`ContentTx::save_draft`], plus the errors of
    /// [`Database::commit`].
    pub fn save_draft(&self, rid: Rid, patch: Patch) -> Result<()> {
        self.db.commit(|tx| {
            tx.content_of(self.engine.collection)
                .save_draft(rid, patch.clone())
        })
    }

    /// Record a revision in its own commit. See
    /// [`ContentTx::save_revision`].
    ///
    /// # Errors
    ///
    /// As [`ContentTx::save_revision`], plus the errors of
    /// [`Database::commit`].
    pub fn save_revision(&self, rid: Rid, message: &str) -> Result<u32> {
        self.db.commit(|tx| {
            tx.content_of(self.engine.collection)
                .save_revision(rid, message)
        })
    }

    /// Publish in its own commit. See [`ContentTx::publish`].
    ///
    /// # Errors
    ///
    /// As [`ContentTx::publish`], plus the errors of [`Database::commit`].
    pub fn publish(&self, rid: Rid) -> Result<u32> {
        self.db
            .commit(|tx| tx.content_of(self.engine.collection).publish(rid))
    }

    /// Unpublish in its own commit. See [`ContentTx::unpublish`].
    ///
    /// # Errors
    ///
    /// As [`ContentTx::unpublish`], plus the errors of [`Database::commit`].
    pub fn unpublish(&self, rid: Rid) -> Result<bool> {
        self.db
            .commit(|tx| tx.content_of(self.engine.collection).unpublish(rid))
    }

    /// Trash an entity in its own commit. See [`ContentTx::trash`].
    ///
    /// # Errors
    ///
    /// As [`ContentTx::trash`], plus the errors of [`Database::commit`].
    pub fn trash(&self, rid: Rid) -> Result<()> {
        self.db
            .commit(|tx| tx.content_of(self.engine.collection).trash(rid))
    }

    /// Restore an entity in its own commit. See [`ContentTx::restore`].
    ///
    /// # Errors
    ///
    /// As [`ContentTx::restore`], plus the errors of [`Database::commit`].
    pub fn restore(&self, rid: Rid) -> Result<()> {
        self.db
            .commit(|tx| tx.content_of(self.engine.collection).restore(rid))
    }

    /// Delete an entity in its own commit. See [`ContentTx::delete`].
    ///
    /// # Errors
    ///
    /// As [`ContentTx::delete`], plus the errors of [`Database::commit`].
    pub fn delete(&self, rid: Rid) -> Result<()> {
        self.db
            .commit(|tx| tx.content_of(self.engine.collection).delete(rid))
    }

    /// The entities that refer to `rid` (other than `rid` itself): through
    /// an [`Entity`](crate::Value::Entity) field of a draft or of a
    /// published body, in any locale. Sorted by record id. One prefix read
    /// of the reference records, which every commit keeps current.
    ///
    /// # Errors
    ///
    /// As [`get`](Self::get).
    pub fn referenced_by(&self, rid: Rid) -> Result<Vec<Rid>> {
        let mut out = self.engine().stored_referrers(rid)?;
        out.retain(|s| *s != rid);
        Ok(out)
    }

    /// The children of `rid` in the page tree, in any status, lowest
    /// [`order`](crate::Entry::order) first (ties by record id): for menus
    /// and section pages. An index read; read each with
    /// [`get`](Self::get) to serve only published ones.
    #[must_use]
    pub fn children(&self, rid: Rid) -> Vec<Rid> {
        self.engine().tree.children(rid)
    }

    /// The ancestors of `rid`, its parent first and the root last: for
    /// breadcrumbs. Empty for an entity at the root or one that does not
    /// exist.
    ///
    /// # Errors
    ///
    /// As [`get`](Self::get).
    pub fn ancestors(&self, rid: Rid) -> Result<Vec<Rid>> {
        let engine = self.engine();
        let mut out = Vec::new();
        let mut at = engine.head(rid)?.and_then(|h| h.parent);
        while let Some(p) = at {
            if out.len() >= MAX_DEPTH || out.contains(&p) {
                break;
            }
            out.push(p);
            at = engine.head(p)?.and_then(|h| h.parent);
        }
        Ok(out)
    }

    /// Schedule `action` for the entity's own locale in its own commit.
    /// See [`ContentTx::schedule_in`].
    ///
    /// ```no_run
    /// # fn main() -> nex_db::Result<()> {
    /// use std::time::{Duration, SystemTime};
    /// use nex_db::{Action, Entity};
    /// let db = nex_db::open("data/site")?;
    /// let rid = db.content().create(Entity::new("post").path("/launch"))?;
    /// let monday = SystemTime::now() + Duration::from_secs(3 * 86_400);
    /// db.content().schedule(rid, Action::Publish, monday)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// As [`ContentTx::schedule_in`], plus the errors of
    /// [`Database::commit`].
    pub fn schedule(&self, rid: Rid, action: Action, at: SystemTime) -> Result<()> {
        self.db.commit(|tx| {
            tx.content_of(self.engine.collection)
                .schedule(rid, action, at)
        })
    }

    /// Fire every schedule due at `now`, each in its own commit; a schedule
    /// whose commit fails is dropped (the failure goes to the observer).
    /// False when a schedule could neither run nor be dropped.
    pub(crate) fn fire_due(&self, now: u64) -> bool {
        let mut done = true;
        for (at, rid, locale, action) in self.engine().schedules.due(now) {
            let fired = self.db.commit(|tx| {
                tx.content_of(self.engine.collection)
                    .fire(rid, locale, action, at)
            });
            if fired.is_err()
                && self
                    .db
                    .commit(|tx| {
                        tx.content_of(self.engine.collection)
                            .clear_schedule(rid, locale, action, at)
                    })
                    .is_err()
            {
                done = false;
            }
        }
        done
    }

    /// Place an entity in the page tree in its own commit. See
    /// [`ContentTx::set_parent`].
    ///
    /// # Errors
    ///
    /// As [`ContentTx::set_parent`], plus the errors of
    /// [`Database::commit`].
    pub fn set_parent(&self, rid: Rid, parent: Option<Rid>) -> Result<()> {
        self.db.commit(|tx| {
            tx.content_of(self.engine.collection)
                .set_parent(rid, parent)
        })
    }

    /// Replace an entity's authors in its own commit. See
    /// [`ContentTx::set_authors`].
    ///
    /// # Errors
    ///
    /// As [`ContentTx::set_authors`], plus the errors of
    /// [`Database::commit`].
    pub fn set_authors(&self, rid: Rid, authors: &[AccountId]) -> Result<()> {
        self.db.commit(|tx| {
            tx.content_of(self.engine.collection)
                .set_authors(rid, authors)
        })
    }

    /// Move an entity in its own commit. See [`ContentTx::set_path`].
    ///
    /// # Errors
    ///
    /// As [`ContentTx::set_path`], plus the errors of [`Database::commit`].
    pub fn set_path(&self, rid: Rid, path: &str) -> Result<()> {
        self.db
            .commit(|tx| tx.content_of(self.engine.collection).set_path(rid, path))
    }
}

/// Every entry of a listing, page by page: an iterator from
/// [`Content::stream`].
#[derive(Debug)]
pub struct Stream<'db> {
    content: Content<'db>,
    listing: Listing,
    after: Option<(u64, [u8; 16])>,
    buffer: std::collections::VecDeque<Entry>,
    done: bool,
}

impl Iterator for Stream<'_> {
    type Item = Result<Entry>;

    fn next(&mut self) -> Option<Result<Entry>> {
        loop {
            if let Some(entry) = self.buffer.pop_front() {
                return Some(Ok(entry));
            }
            if self.done {
                return None;
            }
            match self.content.page(&self.listing, self.after) {
                Ok(page) => {
                    match page.next {
                        Some(cursor) => self.after = Some(cursor.after),
                        None => self.done = true,
                    }
                    self.buffer.extend(page.items);
                }
                Err(err) => {
                    self.done = true;
                    return Some(Err(err));
                }
            }
        }
    }
}

/// Content reads at one snapshot, inside [`Database::read`](crate::Database::read).
///
/// Returned by [`Read::content`](crate::Read::content).
#[derive(Debug)]
pub struct ContentRead<'r> {
    pub(crate) engine: &'r ContentEngine,
    pub(crate) snapshot: &'r SnapshotGuard<'r>,
}

impl ContentRead<'_> {
    fn at(&self) -> Result<Seq> {
        if self.snapshot.expired() {
            return Err(Error::SnapshotTooOld);
        }
        Ok(self.snapshot.seq())
    }

    /// The published revision of `rid` as of the snapshot, or `None`.
    ///
    /// # Errors
    ///
    /// [`Error::SnapshotTooOld`] past the snapshot age limit, and the errors
    /// of [`Content::get`].
    pub fn get(&self, rid: Rid) -> Result<Option<Entry>> {
        let at = self.at()?;
        self.engine.published_in(rid, None, at)
    }

    /// As [`Content::get_in`], as of the snapshot.
    ///
    /// # Errors
    ///
    /// As [`get`](Self::get).
    pub fn get_in(&self, rid: Rid, locale: Locale) -> Result<Option<Entry>> {
        let at = self.at()?;
        self.engine.published_in(rid, Some(locale), at)
    }

    /// The working draft of `rid` as of the snapshot, or `None`.
    ///
    /// # Errors
    ///
    /// As [`get`](Self::get).
    pub fn draft(&self, rid: Rid) -> Result<Option<Entry>> {
        let at = self.at()?;
        self.engine.draft_in(rid, None, at)
    }

    /// The route at `path` on `site` as of the snapshot, or `None`.
    ///
    /// # Errors
    ///
    /// [`Error::SnapshotTooOld`] past the snapshot age limit.
    pub fn resolve(&self, site: &str, path: &str) -> Result<Option<RouteEntry>> {
        let at = self.at()?;
        Ok(self.engine.routes.get_at(site, path, at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_key_separates_site_and_path() {
        assert_ne!(route_key("a", "/bc"), route_key("a/", "bc"));
    }

    #[test]
    fn test_keys_start_with_their_prefixes() {
        let rid = Rid::from_bytes([4; 16]);
        assert!(entity_key(2, rid).starts_with(&entity_prefix(2)));
        assert!(!entity_key(2, rid).starts_with(META_APPLIED));
        assert!(revision_key(2, rid, 7).starts_with(&revision_prefix(2, rid)));
        assert!(stored_route_key(2, "a", "/b").starts_with(&route_prefix(2)));
        let name = &stored_route_key(2, "a.com", "/x/y")[route_prefix(2).len()..];
        assert_eq!(split_route(name, 0).unwrap(), ("a.com", "/x/y"));
    }

    #[test]
    fn test_after_bounds_a_prefix_scan() {
        assert_eq!(after(&[1, 2]), vec![1, 3]);
        assert_eq!(after(&[1, 0xFF]), vec![2]);
        assert!(after(&[0xFF]).is_empty());
    }

    #[test]
    fn test_a_create_section_from_0_3_applies_and_reopens_published() {
        let dir = std::env::temp_dir().join(format!(
            "nex-db-content-legacy-{}-{}",
            std::process::id(),
            now_ms()
        ));
        let rid = Rid::from_bytes([6; 16]);
        let home = Rid::from_bytes([7; 16]);
        let record = Entity::new("page")
            .field("title", "Old")
            .field("up", home)
            .path("/old")
            .encode_v1(rid, 3)
            .unwrap();
        let home_record = Entity::new("page").encode_v1(home, 3).unwrap();
        let mut body = Vec::new();
        let mut w = Writer::new(&mut body);
        w.u8(OP_CREATE);
        w.bytes32(&record).unwrap();
        {
            let engine = ContentEngine::open(&dir, 2, Arc::default()).unwrap();
            engine
                .apply(
                    1,
                    &Section {
                        engine: EngineId::CONTENT,
                        flags: 0,
                        format: FORMAT_CREATE_ONLY,
                        collection: 2,
                        body: &body,
                    },
                    &mut Vec::new(),
                )
                .unwrap();
            let route = engine.routes.get(crate::DEFAULT_SITE, "/old").unwrap();
            assert_eq!((route.entity, route.revision), (rid, 1));
            let _ = engine.checkpoint(1).unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);

        // A store written by 0.3 has the records and no route or reference
        // records.
        {
            let store = Lsm::open(&dir).unwrap();
            store.put(entity_key(2, rid), &record).unwrap();
            store.put(entity_key(2, home), &home_record).unwrap();
            store.flush().unwrap();
        }
        let engine = ContentEngine::open(&dir, 2, Arc::default()).unwrap();
        assert!(engine.routes.get(crate::DEFAULT_SITE, "/old").is_some());
        let entry = engine.published_in(rid, None, Seq::MAX).unwrap().unwrap();
        assert_eq!(entry.status(), Status::Published);
        assert_eq!(entry.revision(), 1);
        assert_eq!(entry.field("title").and_then(|v| v.as_text()), Some("Old"));
        // Its references are recorded at open.
        assert_eq!(engine.stored_referrers(home).unwrap(), vec![rid]);

        // Editing it keeps its published body: the record becomes revision 1.
        let mut staged = ContentStaged::new(&engine);
        ContentTx {
            staged: &mut staged,
        }
        .save_draft(rid, Patch::new().set("title", "New").remove("up"))
        .unwrap();
        let mut body = Vec::new();
        staged.encode(2, &mut body).unwrap();
        engine
            .apply(
                2,
                &Section {
                    engine: EngineId::CONTENT,
                    flags: 0,
                    format: FORMAT,
                    collection: 2,
                    body: &body,
                },
                &mut Vec::new(),
            )
            .unwrap();
        let entry = engine.published_in(rid, None, Seq::MAX).unwrap().unwrap();
        assert_eq!(entry.field("title").and_then(|v| v.as_text()), Some("Old"));
        let draft = engine.draft_in(rid, None, Seq::MAX).unwrap().unwrap();
        assert_eq!(draft.field("title").and_then(|v| v.as_text()), Some("New"));
        // The published body still refers to `home`.
        assert_eq!(engine.stored_referrers(home).unwrap(), vec![rid]);
        drop(engine);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_decode_ops_refuses_an_op_of_the_wrong_format() {
        assert!(decode_ops(1, FORMAT_CREATE_ONLY, &[OP_PUT_HEAD]).is_err());
        assert!(decode_ops(1, FORMAT, &[OP_CREATE]).is_err());
        assert!(decode_ops(1, FORMAT, &[0xEE]).is_err());
        let mut link = vec![OP_PUT_LINK];
        link.extend_from_slice(&[1; 32]);
        assert!(decode_ops(1, FORMAT, &link).is_ok());
        assert!(decode_ops(1, FORMAT, &link[..20]).is_err());
        assert!(decode_ops(1, FORMAT_CREATE_ONLY, &link).is_err());
    }
}
