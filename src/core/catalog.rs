//! The catalog: engine 0.
//!
//! The catalog binds every collection to one engine, for good. Its changes
//! are ordinary log records (`kind = Catalog`), applied like any other
//! section, so catalog and data agree at every sequence number. After each
//! change the whole catalog is written to `core/catalog.ckpt` (atomic
//! replace, BLAKE3 checksum), so recovery never needs the catalog's log
//! records again. A checkpoint that fails its checksum keeps the database
//! closed.

use std::{
    path::PathBuf,
    sync::{PoisonError, RwLock},
};

use super::{
    codec::{Reader, Writer},
    fs,
    record::Seq,
};
use crate::{
    engine::{Conflict, Engine, EngineId, Staged},
    error::{Error, Result},
};

/// Catalog checkpoint file name, inside `core/`.
pub(crate) const CHECKPOINT: &str = "catalog.ckpt";

/// Format version of the catalog section and checkpoint.
const FORMAT: u16 = 1;

/// The one catalog operation in this version.
const OP_DEFINE: u8 = 1;

/// Longest collection name.
const MAX_NAME: usize = 64;

/// The default auth realm, created with the database.
pub(crate) const DEFAULT_REALM: Collection = Collection::fixed(1, EngineId::AUTH, "users");

/// The default content space, created with the database.
pub(crate) const DEFAULT_SPACE: Collection = Collection::fixed(2, EngineId::CONTENT, "site");

/// A collection: an id, the engine it belongs to, and a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Collection {
    pub(crate) id: u32,
    pub(crate) engine: EngineId,
    pub(crate) name: std::borrow::Cow<'static, str>,
}

impl Collection {
    const fn fixed(id: u32, engine: EngineId, name: &'static str) -> Self {
        Collection {
            id,
            engine,
            name: std::borrow::Cow::Borrowed(name),
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

    /// Work that defines the default collections, for a new database.
    pub(crate) fn bootstrap() -> CatalogStaged {
        CatalogStaged {
            defines: vec![DEFAULT_REALM, DEFAULT_SPACE],
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

    fn apply(&self, seq: Seq, _collection: u32, format: u16, body: &[u8]) -> Result<()> {
        if format != FORMAT {
            return Err(Error::corrupt("a catalog section format", seq));
        }
        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        if seq <= state.through {
            return Ok(());
        }
        let mut next = state.collections.clone();
        let mut r = Reader::new(body, "a catalog section", seq);
        while !r.is_empty() {
            if r.u8()? != OP_DEFINE {
                return Err(Error::corrupt("a catalog operation", seq));
            }
            let id = r.u32()?;
            let engine = EngineId(r.u16()?);
            let name = r.str16()?;
            match next.iter().find(|c| c.id == id || c.name == name) {
                // A collection's engine never changes.
                Some(existing) if existing.engine != engine || existing.id != id => {
                    return Err(Error::corrupt("a catalog change (engine rebinding)", seq));
                }
                Some(_) => {}
                None => next.push(Collection {
                    id,
                    engine,
                    name: name.to_owned().into(),
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

    fn checkpoint(&self) -> Result<Seq> {
        // Every change is written as it is applied.
        Ok(self.durable_through())
    }
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
            w.u8(OP_DEFINE);
            w.u32(c.id);
            w.u16(c.engine.0);
            w.str16(&c.name)?;
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
        collections.push(Collection { id, engine, name });
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

    fn bootstrap_body() -> Vec<u8> {
        let mut body = Vec::new();
        Catalog::bootstrap().encode(1, &mut body).unwrap();
        body
    }

    #[test]
    fn test_apply_bootstrap_persists_across_open() {
        let dir = temp_dir();
        let catalog = Catalog::open(&dir).unwrap();
        assert!(catalog.is_empty());
        catalog.apply(1, 0, FORMAT, &bootstrap_body()).unwrap();
        drop(catalog);

        let catalog = Catalog::open(&dir).unwrap();
        assert_eq!(catalog.durable_through(), 1);
        assert_eq!(catalog.collection(1), Some(DEFAULT_REALM));
        assert_eq!(catalog.collection(2), Some(DEFAULT_SPACE));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_apply_same_seq_twice_is_skipped() {
        let dir = temp_dir();
        let catalog = Catalog::open(&dir).unwrap();
        catalog.apply(1, 0, FORMAT, &bootstrap_body()).unwrap();
        catalog.apply(1, 0, FORMAT, b"garbage").unwrap();
        assert_eq!(catalog.durable_through(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_apply_engine_rebinding_is_corrupt() {
        let dir = temp_dir();
        let catalog = Catalog::open(&dir).unwrap();
        catalog.apply(1, 0, FORMAT, &bootstrap_body()).unwrap();
        let mut body = Vec::new();
        CatalogStaged {
            defines: vec![Collection::fixed(1, EngineId::CONTENT, "users")],
        }
        .encode(2, &mut body)
        .unwrap();
        assert!(matches!(
            catalog.apply(2, 0, FORMAT, &body),
            Err(Error::Corrupt { .. })
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_open_damaged_checkpoint_is_corrupt() {
        let dir = temp_dir();
        let catalog = Catalog::open(&dir).unwrap();
        catalog.apply(1, 0, FORMAT, &bootstrap_body()).unwrap();
        drop(catalog);
        let path = dir.join(CHECKPOINT);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[4] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(Catalog::open(&dir), Err(Error::Corrupt { .. })));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
