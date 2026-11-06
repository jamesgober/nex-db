//! The content engine: entities and routes.
//!
//! Entities live in an lsm-db store in `content/store/` (its own write-ahead
//! log is off: the commit log is the write-ahead log). The route index is a
//! derived structure: it is rebuilt from the store when the database opens and
//! updated by `apply` in the same commit as the entity it points to.

pub(crate) mod entity;
mod routes;

use std::{
    collections::HashSet,
    fmt,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use lsm_db::{Batch, Lsm};

use self::{
    entity::{Entity, Entry, RouteEntry, RouteKind},
    routes::RouteTable,
};
use crate::{
    Database,
    core::{
        codec::{Reader, Writer},
        conflict::ConflictTable,
        now_ms,
        record::{Section, Seq},
    },
    engine::{Conflict, Engine, EngineId, Staged},
    error::{Error, Result},
    ids::Rid,
};

/// Section format version.
const FORMAT: u16 = 1;

const OP_CREATE: u8 = 1;

/// Key of the store's applied-through mark.
const META_APPLIED: &[u8] = b"\0meta/applied";

fn entity_prefix(collection: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(21);
    key.extend_from_slice(&collection.to_be_bytes());
    key.push(b'e');
    key
}

fn entity_key(collection: u32, rid: Rid) -> Vec<u8> {
    let mut key = entity_prefix(collection);
    key.extend_from_slice(rid.as_bytes());
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

/// The content engine.
pub(crate) struct ContentEngine {
    collection: u32,
    store: Lsm,
    /// Highest seq the store holds.
    applied: AtomicU64,
    routes: RouteTable,
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
        let start = entity_prefix(collection);
        let mut end = start.clone();
        if let Some(last) = end.last_mut() {
            *last += 1;
        }
        for (_, value) in store.scan(start..end)? {
            let entry = Entry::decode(&value, applied)?;
            if let Some((site, path)) = entry.route() {
                routes.insert(site, path, route_entry(&entry));
            }
        }
        Ok(ContentEngine {
            collection,
            store,
            applied: AtomicU64::new(applied),
            routes,
            conflicts: ConflictTable::new(),
        })
    }

    fn get(&self, rid: Rid) -> Result<Option<Entry>> {
        match self.store.get(entity_key(self.collection, rid))? {
            Some(bytes) => Ok(Some(Entry::decode(&bytes, 0)?)),
            None => Ok(None),
        }
    }
}

fn route_entry(entry: &Entry) -> RouteEntry {
    RouteEntry {
        entity: entry.rid(),
        revision: entry.revision(),
        kind: RouteKind::Page,
    }
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
        // Space definitions (sites, fallback chains) arrive with 0.4; until
        // then a space has no definition.
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
        if section.format != FORMAT || section.flags != 0 || section.collection != self.collection {
            return Err(Error::corrupt("a content section header", seq));
        }
        if seq <= self.applied.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut r = Reader::new(section.body, "a content section", seq);
        let mut entries = Vec::new();
        while !r.is_empty() {
            if r.u8()? != OP_CREATE {
                return Err(Error::corrupt("a content operation", seq));
            }
            let record = r.bytes32()?;
            entries.push((Entry::decode(record, seq)?, record));
        }
        let mut batch = Batch::new();
        for (entry, record) in &entries {
            batch.put(entity_key(self.collection, entry.rid()), record);
        }
        batch.put(META_APPLIED, seq.to_le_bytes());
        self.store.write(batch)?;
        self.applied.store(seq, Ordering::Release);
        for (entry, _) in &entries {
            if let Some((site, path)) = entry.route() {
                self.routes.insert(site, path, route_entry(entry));
            }
        }
        Ok(())
    }

    fn durable_through(&self) -> Seq {
        self.applied.load(Ordering::Acquire)
    }

    fn checkpoint(&self) -> Result<Seq> {
        self.store.flush()?;
        Ok(self.durable_through())
    }

    fn reclaim(&self, watermark: Seq) {
        self.conflicts.prune(watermark);
    }
}

/// One transaction's content work.
pub(crate) struct ContentStaged<'e> {
    engine: &'e ContentEngine,
    /// Encoded entity records.
    records: Vec<Vec<u8>>,
    writes: Vec<Vec<u8>>,
    routes: HashSet<Vec<u8>>,
}

impl<'e> ContentStaged<'e> {
    pub(crate) fn new(engine: &'e ContentEngine) -> Self {
        ContentStaged {
            engine,
            records: Vec::new(),
            writes: Vec::new(),
            routes: HashSet::new(),
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
        self.records.is_empty()
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
        for record in &self.records {
            w.u8(OP_CREATE);
            w.bytes32(record)?;
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
            .field("entities", &self.staged.records.len())
            .finish()
    }
}

impl ContentTx<'_, '_> {
    /// Create `entity` and return its record id.
    ///
    /// ```no_run
    /// # fn main() -> nex_db::Result<()> {
    /// use nex_db::Entity;
    /// let db = nex_db::open("data/site")?;
    /// let rid = db.commit(|tx| {
    ///     tx.content().create(Entity::new("page").field("title", "Hello").path("/hello"))
    /// })?;
    /// # let _ = rid;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] (`what = "path"`) when the path is taken on
    ///   its site.
    /// - [`Error::Invalid`] when a name, path, site, or value breaks its rule.
    pub fn create(&mut self, entity: Entity) -> Result<Rid> {
        let engine = self.staged.engine;
        let rid = Rid::generate();
        let record = entity.encode(rid, now_ms())?;
        if let Some(path) = entity.route_path() {
            let site = entity.site_name();
            let key = route_key(site, path);
            if self.staged.routes.contains(&key) || engine.routes.get(site, path).is_some() {
                return Err(Error::AlreadyExists { what: "path" });
            }
            let _ = self.staged.routes.insert(key.clone());
            self.staged.writes.push(key);
        }
        self.staged.writes.push(entity_key(engine.collection, rid));
        self.staged.records.push(record);
        Ok(rid)
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

    /// The entity with `rid`, or `None`.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] when the store cannot be read, [`Error::Corrupt`]
    /// when the stored record fails its checks.
    pub fn get(&self, rid: Rid) -> Result<Option<Entry>> {
        self.engine().get(rid)
    }

    /// The route at `path` on `site`, or `None`. Reads memory only and
    /// allocates nothing.
    ///
    /// ```no_run
    /// # fn main() -> nex_db::Result<()> {
    /// let db = nex_db::open("data/site")?;
    /// if let Some(route) = db.content().resolve("example.com", "/u/ann")? {
    ///     let page = db.content().get(route.entity())?;
    ///     # let _ = page;
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_key_separates_site_and_path() {
        assert_ne!(route_key("a", "/bc"), route_key("a/", "bc"));
    }

    #[test]
    fn test_entity_key_starts_with_prefix() {
        let rid = Rid::from_bytes([4; 16]);
        assert!(entity_key(2, rid).starts_with(&entity_prefix(2)));
        assert!(!entity_key(2, rid).starts_with(META_APPLIED));
    }
}
