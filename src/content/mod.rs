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
mod routes;

use std::{
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use lsm_db::{Batch, Lsm};

use self::{
    entity::{
        Body, Entity, Entry, Head, Patch, Published, Revision, RevisionInfo, RouteEntry, RouteKind,
        Status, Visibility, decode_route, encode_route,
    },
    routes::RouteTable,
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
    ids::Rid,
};

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
    /// Entity head versions kept for running snapshots.
    versions: Versions,
    conflicts: ConflictTable,
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
    pub(crate) fn open(dir: &Path, collection: u32) -> Result<Self> {
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
        // Entities stored by 0.1 to 0.3 have no route records: their routes
        // come from the entities themselves.
        let start = entity_prefix(collection);
        for (_, value) in store.scan(start.clone()..after(&start))? {
            if Head::is_legacy(&value) {
                let head = Head::decode(&value, applied)?;
                if let Some(path) = head.draft.path.as_deref() {
                    routes.set(&head.site, path, 0, Some(page(&head, 1)));
                }
            }
        }
        let start = route_prefix(collection);
        for (key, value) in store.scan(start.clone()..after(&start))? {
            let name = key.get(start.len()..).unwrap_or_default();
            let (site, path) = split_route(name, applied)?;
            routes.set(site, path, 0, Some(decode_route(&value, applied)?));
        }
        Ok(ContentEngine {
            collection,
            dir: dir.to_path_buf(),
            store,
            applied: AtomicU64::new(applied),
            durable: AtomicU64::new(applied),
            writing: Mutex::new(()),
            routes,
            versions: Versions::new(),
            conflicts: ConflictTable::new(),
        })
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

    fn head(&self, rid: Rid) -> Result<Option<Head>> {
        self.head_at(rid, Seq::MAX)
    }

    fn revision(&self, rid: Rid, n: u32) -> Result<Option<Revision>> {
        self.store
            .get(revision_key(self.collection, rid, n))?
            .map(|bytes| Revision::decode(&bytes, 0))
            .transpose()
    }

    /// The published entry of `rid` as a snapshot at `at` sees it.
    fn published_at(&self, rid: Rid, at: Seq) -> Result<Option<Entry>> {
        let Some(bytes) = self.head_bytes_at(rid, at)? else {
            return Ok(None);
        };
        let head = Head::decode(&bytes, at)?;
        let Some(published) = head.published.clone() else {
            return Ok(None);
        };
        // A record from 0.1 to 0.3 is its own published body.
        let mut body = if Head::is_legacy(&bytes) {
            head.draft.clone()
        } else {
            match self.revision(rid, published.revision)? {
                Some(revision) => revision.body,
                None => return Err(Error::corrupt("an entity without its revision", at)),
            }
        };
        // The path can move without a new revision.
        body.path = published.path;
        Ok(Some(head.entry(published.revision, body)))
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

/// The page route of `head` at `revision`.
fn page(head: &Head, revision: u32) -> RouteEntry {
    RouteEntry {
        entity: head.rid,
        revision,
        kind: RouteKind::Page,
        visibility: head.visibility,
    }
}

/// One operation as read from a section.
enum Op<'a> {
    Create(&'a [u8]),
    PutHead(Rid, &'a [u8]),
    PutRevision(Rid, u32, &'a [u8]),
    PutRoute(&'a str, &'a str, &'a [u8]),
    DeleteRoute(&'a str, &'a str),
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
        // Space definitions (sites, fallback chains) arrive later in 0.4;
        // until then a space has no definition.
        if definition.is_empty() {
            Ok(())
        } else {
            Err(Error::invalid(
                "space definition",
                "must be empty in this version",
            ))
        }
    }

    fn apply(&self, seq: Seq, section: &Section<'_>) -> Result<()> {
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
        for op in &ops {
            match op {
                Op::Create(record) => {
                    let head = Head::decode(record, seq)?;
                    let key = entity_key(self.collection, head.rid);
                    self.versions
                        .record(&key, seq, Some(record), || Ok(self.store.get(&key)?))?;
                    batch.put(key, record);
                    if let Some(path) = head.draft.path.as_deref() {
                        let entry = page(&head, 1);
                        let stored = stored_route_key(self.collection, &head.site, path);
                        batch.put(stored, encode_route(&entry));
                        routes.push((head.site.clone(), path.to_owned(), Some(entry)));
                    }
                }
                Op::PutHead(rid, value) => {
                    let key = entity_key(self.collection, *rid);
                    self.versions
                        .record(&key, seq, Some(value), || Ok(self.store.get(&key)?))?;
                    batch.put(key, *value);
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
}

/// One transaction's content work.
pub(crate) struct ContentStaged<'e> {
    engine: &'e ContentEngine,
    /// Heads as this work left them, in the order first touched.
    heads: Vec<Head>,
    ops: Vec<StagedOp>,
    /// Revisions this work recorded, by entity and number.
    revisions: HashMap<(Rid, u32), Body>,
    /// Routes as this work left them.
    routes: HashMap<(String, String), Option<RouteEntry>>,
    writes: Vec<Vec<u8>>,
}

impl<'e> ContentStaged<'e> {
    pub(crate) fn new(engine: &'e ContentEngine) -> Self {
        ContentStaged {
            engine,
            heads: Vec::new(),
            ops: Vec::new(),
            revisions: HashMap::new(),
            routes: HashMap::new(),
            writes: Vec::new(),
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
        self.heads.is_empty() && self.ops.is_empty()
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
            }
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
        if let Some(head) = self.staged.heads.iter().find(|h| h.rid == rid) {
            return Ok(head.clone());
        }
        self.staged
            .engine
            .head(rid)?
            .ok_or_else(|| Error::invalid("entity", "no such entity"))
    }

    fn put_head(&mut self, mut head: Head) {
        head.updated_ms = now_ms();
        let key = entity_key(self.staged.engine.collection, head.rid);
        match self.staged.heads.iter_mut().find(|h| h.rid == head.rid) {
            Some(slot) => *slot = head,
            None => {
                self.staged.heads.push(head);
                self.staged.writes.push(key);
            }
        }
    }

    /// The route at `path` on `site` as this transaction sees it.
    fn route(&self, site: &str, path: &str) -> Option<RouteEntry> {
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

    /// Refuse `path` on `site` when another entity's page is there.
    /// Redirects and gone markers give way.
    fn check_free(&self, site: &str, path: &str, rid: Rid) -> Result<()> {
        match self.route(site, path) {
            Some(RouteEntry {
                entity,
                kind: RouteKind::Page,
                ..
            }) if entity != rid => Err(Error::AlreadyExists { what: "path" }),
            _ => Ok(()),
        }
    }

    /// Serve `head` at its published path at `revision`, and leave the old
    /// published path, if it differs, as a 301 to the entity.
    fn route_published(&mut self, head: &Head, old: Option<&str>) -> Result<()> {
        let Some(published) = &head.published else {
            return Ok(());
        };
        let new = published.path.as_deref();
        if let Some(path) = new {
            self.check_free(&head.site, path, head.rid)?;
            self.put_route(&head.site, path, Some(page(head, published.revision)));
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
            };
            self.put_route(&head.site, old, Some(moved));
        }
        Ok(())
    }

    /// The body of revision `n` of `rid` as this transaction sees it.
    fn revision_body(&self, rid: Rid, n: u32) -> Result<Option<Body>> {
        if let Some(body) = self.staged.revisions.get(&(rid, n)) {
            return Ok(Some(body.clone()));
        }
        Ok(self.staged.engine.revision(rid, n)?.map(|r| r.body))
    }

    fn record_revision(&mut self, head: &mut Head, message: &str) -> Result<u32> {
        let n = head
            .last_revision
            .checked_add(1)
            .ok_or_else(|| Error::invalid("entity", "has too many revisions"))?;
        let revision = Revision::new(now_ms(), message, head.draft.clone())?;
        self.staged
            .ops
            .push(StagedOp::Revision(head.rid, n, revision.encode()?));
        let _ = self
            .staged
            .revisions
            .insert((head.rid, n), head.draft.clone());
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
        let head = entity.into_head(rid, now_ms())?;
        if let Some(path) = head.draft.path.as_deref() {
            self.check_free(&head.site, path, rid)?;
        }
        self.put_head(head);
        Ok(rid)
    }

    /// Change the working draft. Records no revision.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the entity does not exist or the result
    /// breaks a rule of [`create`](Self::create).
    pub fn save_draft(&mut self, rid: Rid, patch: Patch) -> Result<()> {
        let mut head = self.head(rid)?;
        patch.apply(&mut head.draft)?;
        self.put_head(head);
        Ok(())
    }

    /// Record the working draft as a fixed revision with `message` (at most
    /// 1,024 bytes) and return its number.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the entity does not exist or the message is
    /// too long.
    pub fn save_revision(&mut self, rid: Rid, message: &str) -> Result<u32> {
        let mut head = self.head(rid)?;
        let n = self.record_revision(&mut head, message)?;
        self.put_head(head);
        Ok(n)
    }

    /// Publish the working draft and return the published revision: the
    /// newest one when the draft has not changed since it, else a new one.
    /// The entity is then served at the draft's path; a different path it
    /// was published at before becomes a 301 to it.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] (`what = "path"`) when another entity is
    ///   served at the path.
    /// - [`Error::Invalid`] when the entity does not exist or is trashed.
    pub fn publish(&mut self, rid: Rid) -> Result<u32> {
        let mut head = self.head(rid)?;
        if head.status == Status::Trashed {
            return Err(Error::invalid("entity", "is in the trash"));
        }
        let unchanged = head.last_revision > 0
            && self.revision_body(rid, head.last_revision)?.as_ref() == Some(&head.draft);
        let n = if unchanged {
            head.last_revision
        } else {
            self.record_revision(&mut head, "")?
        };
        let old = head.published.take().and_then(|p| p.path);
        let now = now_ms();
        head.published = Some(Published {
            revision: n,
            at_ms: now,
            path: head.draft.path.clone(),
        });
        if head.first_published_ms == 0 {
            head.first_published_ms = now;
        }
        head.status = Status::Published;
        self.route_published(&head, old.as_deref())?;
        self.put_head(head);
        Ok(n)
    }

    /// Stop serving the entity: its path no longer resolves and
    /// [`Content::get`] finds nothing. The draft and revisions stay; the
    /// status becomes [`Status::Draft`]. Returns `false` when nothing was
    /// published.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the entity does not exist.
    pub fn unpublish(&mut self, rid: Rid) -> Result<bool> {
        let mut head = self.head(rid)?;
        let Some(published) = head.published.take() else {
            return Ok(false);
        };
        if let Some(path) = published.path {
            self.put_route(&head.site, &path, None);
        }
        head.status = Status::Draft;
        self.put_head(head);
        Ok(true)
    }

    /// Serve the entity at `path` from now on: the draft's path changes,
    /// and when the entity is published, it moves at once and its old path
    /// becomes a 301 to it.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] (`what = "path"`) when another entity is
    ///   served at the path.
    /// - [`Error::Invalid`] when the entity does not exist or the path
    ///   breaks its rule.
    pub fn set_path(&mut self, rid: Rid, path: &str) -> Result<()> {
        let mut head = self.head(rid)?;
        Patch::new().path(path).apply(&mut head.draft)?;
        self.check_free(&head.site, path, rid)?;
        if let Some(published) = head.published.as_mut() {
            let old = published.path.replace(path.to_owned());
            self.route_published(&head, old.as_deref())?;
        }
        self.put_head(head);
        Ok(())
    }

    /// Set the entity's status to `status`: [`Status::Draft`] or
    /// [`Status::Review`] for an unpublished entity, or
    /// [`Status::Archived`], which also unpublishes it.
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
                if self.head(rid)?.published.is_some() {
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
        self.put_head(head);
        Ok(())
    }

    /// Set who may see the entity. A published entity's route carries the
    /// change at once.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the entity does not exist.
    pub fn set_visibility(&mut self, rid: Rid, visibility: Visibility) -> Result<()> {
        let mut head = self.head(rid)?;
        head.visibility = visibility;
        if let Some(published) = &head.published {
            if let Some(path) = &published.path {
                let entry = page(&head, published.revision);
                let path = path.clone();
                self.put_route(&head.site.clone(), &path, Some(entry));
            }
        }
        self.put_head(head);
        Ok(())
    }
}

/// The content engine's operations outside a transaction.
///
/// Returned by [`Database::content`].
#[derive(Debug, Clone, Copy)]
pub struct Content<'db> {
    pub(crate) db: &'db Database,
}

impl Content<'_> {
    fn engine(&self) -> &ContentEngine {
        self.db.content_engine()
    }

    /// The published revision of `rid`, or `None` when nothing is
    /// published (or the entity does not exist).
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] when the store cannot be read, [`Error::Corrupt`]
    /// when a stored record fails its checks.
    pub fn get(&self, rid: Rid) -> Result<Option<Entry>> {
        self.engine().published_at(rid, Seq::MAX)
    }

    /// The working draft of `rid`, for editors, or `None` when the entity
    /// does not exist.
    ///
    /// # Errors
    ///
    /// As [`get`](Self::get).
    pub fn draft(&self, rid: Rid) -> Result<Option<Entry>> {
        Ok(self
            .engine()
            .head(rid)?
            .map(|head| head.entry(head.last_revision, head.draft.clone())))
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
        Ok(engine.revision(rid, n)?.map(|r| head.entry(n, r.body)))
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

    /// Create an entity in its own commit. See [`ContentTx::create`].
    ///
    /// # Errors
    ///
    /// As [`ContentTx::create`], plus the errors of [`Database::commit`].
    pub fn create(&self, entity: Entity) -> Result<Rid> {
        self.db.commit(|tx| tx.content().create(entity.clone()))
    }

    /// Change a draft in its own commit. See [`ContentTx::save_draft`].
    ///
    /// # Errors
    ///
    /// As [`ContentTx::save_draft`], plus the errors of
    /// [`Database::commit`].
    pub fn save_draft(&self, rid: Rid, patch: Patch) -> Result<()> {
        self.db
            .commit(|tx| tx.content().save_draft(rid, patch.clone()))
    }

    /// Record a revision in its own commit. See
    /// [`ContentTx::save_revision`].
    ///
    /// # Errors
    ///
    /// As [`ContentTx::save_revision`], plus the errors of
    /// [`Database::commit`].
    pub fn save_revision(&self, rid: Rid, message: &str) -> Result<u32> {
        self.db
            .commit(|tx| tx.content().save_revision(rid, message))
    }

    /// Publish in its own commit. See [`ContentTx::publish`].
    ///
    /// # Errors
    ///
    /// As [`ContentTx::publish`], plus the errors of [`Database::commit`].
    pub fn publish(&self, rid: Rid) -> Result<u32> {
        self.db.commit(|tx| tx.content().publish(rid))
    }

    /// Unpublish in its own commit. See [`ContentTx::unpublish`].
    ///
    /// # Errors
    ///
    /// As [`ContentTx::unpublish`], plus the errors of [`Database::commit`].
    pub fn unpublish(&self, rid: Rid) -> Result<bool> {
        self.db.commit(|tx| tx.content().unpublish(rid))
    }

    /// Move an entity in its own commit. See [`ContentTx::set_path`].
    ///
    /// # Errors
    ///
    /// As [`ContentTx::set_path`], plus the errors of [`Database::commit`].
    pub fn set_path(&self, rid: Rid, path: &str) -> Result<()> {
        self.db.commit(|tx| tx.content().set_path(rid, path))
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
        self.engine.published_at(rid, at)
    }

    /// The working draft of `rid` as of the snapshot, or `None`.
    ///
    /// # Errors
    ///
    /// As [`get`](Self::get).
    pub fn draft(&self, rid: Rid) -> Result<Option<Entry>> {
        let at = self.at()?;
        Ok(self
            .engine
            .head_at(rid, at)?
            .map(|head| head.entry(head.last_revision, head.draft.clone())))
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
        let record = Entity::new("page")
            .field("title", "Old")
            .path("/old")
            .encode_v1(rid, 3)
            .unwrap();
        let mut body = Vec::new();
        let mut w = Writer::new(&mut body);
        w.u8(OP_CREATE);
        w.bytes32(&record).unwrap();
        {
            let engine = ContentEngine::open(&dir, 2).unwrap();
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
                )
                .unwrap();
            let route = engine.routes.get(crate::DEFAULT_SITE, "/old").unwrap();
            assert_eq!((route.entity, route.revision), (rid, 1));
            let _ = engine.checkpoint(1).unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);

        // A store written by 0.3 has the record and no route records.
        {
            let store = Lsm::open(&dir).unwrap();
            store.put(entity_key(2, rid), &record).unwrap();
            store.flush().unwrap();
        }
        let engine = ContentEngine::open(&dir, 2).unwrap();
        assert!(engine.routes.get(crate::DEFAULT_SITE, "/old").is_some());
        let entry = engine.published_at(rid, Seq::MAX).unwrap().unwrap();
        assert_eq!(entry.status(), Status::Published);
        assert_eq!(entry.revision(), 1);
        assert_eq!(entry.field("title").and_then(|v| v.as_text()), Some("Old"));
        drop(engine);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_decode_ops_refuses_an_op_of_the_wrong_format() {
        assert!(decode_ops(1, FORMAT_CREATE_ONLY, &[OP_PUT_HEAD]).is_err());
        assert!(decode_ops(1, FORMAT, &[OP_CREATE]).is_err());
        assert!(decode_ops(1, FORMAT, &[0xEE]).is_err());
    }
}
