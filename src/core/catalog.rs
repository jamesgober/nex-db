//! The catalog: engine 0.
//!
//! The catalog binds every collection to one engine, for good, and keeps the
//! collection's definition: bytes the engine checked when the collection was
//! created and that only the engine interprets. Its changes
//! are ordinary log records (`kind = Catalog`), applied like any other
//! section, so catalog and data agree at every sequence number. After each
//! change the whole catalog is written to `core/catalog.ckpt` (atomic
//! replace, BLAKE3 checksum), so recovery never needs the catalog's log
//! records again. A checkpoint that fails its checksum keeps the database
//! closed.

use std::{
    borrow::Cow,
    path::PathBuf,
    sync::{PoisonError, RwLock},
};

use super::{
    codec::{Reader, Writer},
    fs,
    record::{Section, Seq},
};
use crate::{
    engine::{Conflict, Engine, EngineId, Staged},
    error::{Error, Result},
};

/// Catalog checkpoint file name, inside `core/`.
pub(crate) const CHECKPOINT: &str = "catalog.ckpt";

/// Format version of the catalog section and checkpoint. Format 2 added the
/// collection definition; format 1 was never released.
const FORMAT: u16 = 2;

/// The one catalog operation in this version.
const OP_DEFINE: u8 = 1;

/// Longest collection name.
pub(crate) const MAX_NAME: usize = 64;

/// Longest collection definition.
pub(crate) const MAX_DEFINITION: usize = 64 * 1024;

/// The default auth realm, created with the database.
pub(crate) const DEFAULT_REALM: Collection = Collection::fixed(1, EngineId::AUTH, "users");

/// The default content space, created with the database.
pub(crate) const DEFAULT_SPACE: Collection = Collection::fixed(2, EngineId::CONTENT, "site");

/// A collection: an id, the engine it belongs to, a name, and the engine's
/// definition of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Collection {
    pub(crate) id: u32,
    pub(crate) engine: EngineId,
    pub(crate) name: Cow<'static, str>,
    pub(crate) definition: Cow<'static, [u8]>,
}

impl Collection {
    const fn fixed(id: u32, engine: EngineId, name: &'static str) -> Self {
        Collection {
            id,
            engine,
            name: Cow::Borrowed(name),
            definition: Cow::Borrowed(&[]),
        }
    }
}

#[derive(Debug, Default)]
struct State {
    through: Seq,
    collections: Vec<Collection>,
}

/// The catalog engine.
#[derive(Debug)]
pub(crate) struct Catalog {
    path: PathBuf,
    state: RwLock<State>,
}

impl Catalog {
    /// Load the catalog from `core/catalog.ckpt`, or start empty when the
    /// file does not exist.
    pub(crate) fn open(core_dir: &std::path::Path) -> Result<Self> {
        let path = core_dir.join(CHECKPOINT);
        let state = match fs::read_optional(&path)? {
            Some(bytes) => decode_checkpoint(&bytes)?,
            None => State::default(),
        };
        Ok(Catalog {
            path,
            state: RwLock::new(state),
        })
    }

    /// True when no checkpoint was ever written.
    pub(crate) fn is_empty(&self) -> bool {
        let state = self.state.read().unwrap_or_else(PoisonError::into_inner);
        state.through == 0 && state.collections.is_empty()
    }

    /// The collection with `id`, if defined.
    pub(crate) fn collection(&self, id: u32) -> Option<Collection> {
        let state = self.state.read().unwrap_or_else(PoisonError::into_inner);
        state.collections.iter().find(|c| c.id == id).cloned()
    }

    /// True when `id` is defined and bound to `engine`. Checked for every
    /// section before it reaches its engine; allocates nothing.
    pub(crate) fn binds(&self, id: u32, engine: EngineId) -> bool {
        let state = self.state.read().unwrap_or_else(PoisonError::into_inner);
        state
            .collections
            .iter()
            .any(|c| c.id == id && c.engine == engine)
    }

    /// The collection named `name`, if defined.
    pub(crate) fn named(&self, name: &str) -> Option<Collection> {
        let state = self.state.read().unwrap_or_else(PoisonError::into_inner);
        state.collections.iter().find(|c| c.name == name).cloned()
    }

    /// The id the next new collection gets: one above the highest in use.
    pub(crate) fn next_id(&self) -> Option<u32> {
        let state = self.state.read().unwrap_or_else(PoisonError::into_inner);
        state
            .collections
            .iter()
            .map(|c| c.id)
            .max()
            .unwrap_or(0)
            .checked_add(1)
    }
}

impl CatalogStaged {
    /// Work that defines `collections`.
    pub(crate) fn define(collections: Vec<Collection>) -> CatalogStaged {
        CatalogStaged {
            defines: collections,
        }
    }
}

impl Engine for Catalog {
    fn id(&self) -> EngineId {
        EngineId::CATALOG
    }

    fn name(&self) -> &'static str {
        "catalog"
    }

    fn format(&self) -> u16 {
        FORMAT
    }

    fn define(&self, _definition: &[u8]) -> Result<()> {
        Err(Error::invalid("engine", "the catalog holds no collections"))
    }

    fn apply(&self, seq: Seq, section: &Section<'_>) -> Result<()> {
        if section.format != FORMAT || section.flags != 0 {
            return Err(Error::corrupt("a catalog section format", seq));
        }
        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        if seq <= state.through {
            return Ok(());
        }
        let mut next = state.collections.clone();
        let mut r = Reader::new(section.body, "a catalog section", seq);
        while !r.is_empty() {
            if r.u8()? != OP_DEFINE {
                return Err(Error::corrupt("a catalog operation", seq));
            }
            let id = r.u32()?;
            let engine = EngineId(r.u16()?);
            let name = r.str16()?;
            let definition = r.bytes32()?;
            match next.iter().find(|c| c.id == id || c.name == name) {
                // A collection's engine and definition never change here.
                Some(existing)
                    if existing.engine != engine
                        || existing.id != id
                        || *existing.definition != *definition =>
                {
                    return Err(Error::corrupt("a catalog change (rebinding)", seq));
                }
                Some(_) => {}
                None => next.push(Collection {
                    id,
                    engine,
                    name: name.to_owned().into(),
                    definition: definition.to_vec().into(),
                }),
            }
        }
        let bytes = encode_checkpoint(seq, &next)?;
        fs::write_atomic(&self.path, &bytes)?;
        state.collections = next;
        state.through = seq;
        Ok(())
    }

    fn durable_through(&self) -> Seq {
        self.state
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .through
    }

    fn checkpoint(&self, upto: Seq) -> Result<Seq> {
        // Every change is written as it is applied, so the catalog holds
        // everything through any point.
        Ok(upto.max(self.durable_through()))
    }

    fn reclaim(&self, _watermark: Seq) {}
}

/// Catalog work in one transaction.
#[derive(Debug)]
pub(crate) struct CatalogStaged {
    defines: Vec<Collection>,
}

impl Staged for CatalogStaged {
    fn engine(&self) -> EngineId {
        EngineId::CATALOG
    }

    fn collection(&self) -> u32 {
        0
    }

    fn is_empty(&self) -> bool {
        self.defines.is_empty()
    }

    fn validate(&self, _snapshot: Seq) -> std::result::Result<(), Conflict> {
        // Catalog changes run alone, inside the commit lock.
        Ok(())
    }

    fn reserve(&self, _seq: Seq) {}

    fn encode(&self, _seq: Seq, out: &mut Vec<u8>) -> Result<()> {
        let mut w = Writer::new(out);
        for c in &self.defines {
            if c.name.is_empty() || c.name.len() > MAX_NAME {
                return Err(Error::invalid("collection name", "must be 1 to 64 bytes"));
            }
            if c.definition.len() > MAX_DEFINITION {
                return Err(Error::invalid(
                    "collection definition",
                    "larger than 64 KiB",
                ));
            }
            w.u8(OP_DEFINE);
            w.u32(c.id);
            w.u16(c.engine.0);
            w.str16(&c.name)?;
            w.bytes32(&c.definition)?;
        }
        Ok(())
    }
}

fn encode_checkpoint(through: Seq, collections: &[Collection]) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut w = Writer::new(&mut buf);
    w.u16(FORMAT);
    w.u64(through);
    w.u32(u32::try_from(collections.len()).map_err(|_| Error::invalid("catalog", "too large"))?);
    for c in collections {
        w.u32(c.id);
        w.u16(c.engine.0);
        w.str16(&c.name)?;
        w.bytes32(&c.definition)?;
    }
    let sum = crypt_io::hash::blake3(&buf);
    buf.extend_from_slice(&sum);
    Ok(buf)
}

fn decode_checkpoint(bytes: &[u8]) -> Result<State> {
    let corrupt = || Error::corrupt("the catalog checkpoint", 0);
    let split = bytes.len().checked_sub(32).ok_or_else(corrupt)?;
    let (body, sum) = bytes.split_at(split);
    if crypt_io::hash::blake3(body)[..] != *sum {
        return Err(corrupt());
    }
    let mut r = Reader::new(body, "the catalog checkpoint", 0);
    if r.u16()? != FORMAT {
        return Err(corrupt());
    }
    let through = r.u64()?;
    let count = r.u32()?;
    let mut collections = Vec::new();
    for _ in 0..count {
        let id = r.u32()?;
        let engine = EngineId(r.u16()?);
        let name = r.str16()?.to_owned().into();
        let definition = r.bytes32()?.to_vec().into();
        collections.push(Collection {
            id,
            engine,
            name,
            definition,
        });
    }
    r.finish()?;
    Ok(State {
        through,
        collections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nex-db-catalog-{}-{}",
            std::process::id(),
            id_forge::ulid::Ulid::new()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn section(body: &[u8]) -> Section<'_> {
        Section {
            engine: EngineId::CATALOG,
            flags: 0,
            format: FORMAT,
            collection: 0,
            body,
        }
    }

    fn bootstrap_body() -> Vec<u8> {
        let mut body = Vec::new();
        CatalogStaged::define(vec![DEFAULT_REALM, DEFAULT_SPACE])
            .encode(1, &mut body)
            .unwrap();
        body
    }

    #[test]
    fn test_apply_bootstrap_persists_across_open() {
        let dir = temp_dir();
        let catalog = Catalog::open(&dir).unwrap();
        assert!(catalog.is_empty());
        catalog.apply(1, &section(&bootstrap_body())).unwrap();
        drop(catalog);

        let catalog = Catalog::open(&dir).unwrap();
        assert_eq!(catalog.durable_through(), 1);
        assert_eq!(catalog.collection(1), Some(DEFAULT_REALM));
        assert_eq!(catalog.collection(2), Some(DEFAULT_SPACE));
        assert!(catalog.binds(1, EngineId::AUTH));
        assert!(!catalog.binds(1, EngineId::CONTENT));
        assert_eq!(catalog.next_id(), Some(3));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_definition_round_trips_through_checkpoint() {
        let dir = temp_dir();
        let catalog = Catalog::open(&dir).unwrap();
        let mut body = Vec::new();
        CatalogStaged::define(vec![Collection {
            id: 7,
            engine: EngineId(9),
            name: "notes".into(),
            definition: b"def".to_vec().into(),
        }])
        .encode(1, &mut body)
        .unwrap();
        catalog.apply(1, &section(&body)).unwrap();
        drop(catalog);
        let catalog = Catalog::open(&dir).unwrap();
        let notes = catalog.named("notes").unwrap();
        assert_eq!((notes.id, &*notes.definition), (7, &b"def"[..]));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_apply_same_seq_twice_is_skipped() {
        let dir = temp_dir();
        let catalog = Catalog::open(&dir).unwrap();
        catalog.apply(1, &section(&bootstrap_body())).unwrap();
        catalog.apply(1, &section(b"garbage")).unwrap();
        assert_eq!(catalog.durable_through(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_apply_engine_rebinding_is_corrupt() {
        let dir = temp_dir();
        let catalog = Catalog::open(&dir).unwrap();
        catalog.apply(1, &section(&bootstrap_body())).unwrap();
        let mut body = Vec::new();
        CatalogStaged::define(vec![Collection::fixed(1, EngineId::CONTENT, "users")])
            .encode(2, &mut body)
            .unwrap();
        assert!(matches!(
            catalog.apply(2, &section(&body)),
            Err(Error::Corrupt { .. })
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_open_damaged_checkpoint_is_corrupt() {
        let dir = temp_dir();
        let catalog = Catalog::open(&dir).unwrap();
        catalog.apply(1, &section(&bootstrap_body())).unwrap();
        drop(catalog);
        let path = dir.join(CHECKPOINT);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[4] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(Catalog::open(&dir), Err(Error::Corrupt { .. })));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
