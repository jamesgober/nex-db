//! A toy engine that proves the contract.
//!
//! The toy engine stores `u16 -> u64` cells: a transaction stages `put`s, the
//! section body is `key u16 | value u64` per put, and a checkpoint writes the
//! whole map with its durable mark to one file. It is hosted on the core with
//! no auth or content engine present, under an id the real engines never
//! use, so these tests show that the commit pipeline, recovery, and the
//! catalog work for any engine that follows the contract.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

use super::{Conflict, Engine, EngineId, Registry, Staged};
use crate::{
    core::{
        codec::{Reader, Writer},
        conflict::ConflictTable,
        fs,
        log::CommitLog,
        pipeline::{Attempt, Core},
        record::{self, Class, Section, Seq},
    },
    error::{Error, Result},
};

const FORMAT: u16 = 1;

/// The only definition the toy engine accepts: format byte 1, then anything.
const DEFINITION: &[u8] = &[1, b't', b'o', b'y'];

struct ToyEngine {
    id: EngineId,
    file: PathBuf,
    cells: Mutex<BTreeMap<u16, u64>>,
    applied: AtomicU64,
    durable: AtomicU64,
    /// Sections actually installed (not skipped), to watch replay.
    installs: AtomicUsize,
    conflicts: ConflictTable,
}

impl ToyEngine {
    fn open(dir: &Path, id: EngineId) -> Result<Self> {
        fs::create_dir(dir)?;
        let file = dir.join(format!("toy-{}.state", id.0));
        let mut cells = BTreeMap::new();
        let mut through = 0;
        if let Some(bytes) = fs::read_optional(&file)? {
            let mut r = Reader::new(&bytes, "a toy checkpoint", 0);
            through = r.u64()?;
            while !r.is_empty() {
                let _ = cells.insert(r.u16()?, r.u64()?);
            }
        }
        Ok(ToyEngine {
            id,
            file,
            cells: Mutex::new(cells),
            applied: AtomicU64::new(through),
            durable: AtomicU64::new(through),
            installs: AtomicUsize::new(0),
            conflicts: ConflictTable::new(),
        })
    }

    fn get(&self, key: u16) -> Option<u64> {
        self.cells
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
            .copied()
    }
}

impl Engine for ToyEngine {
    fn id(&self) -> EngineId {
        self.id
    }

    fn name(&self) -> &'static str {
        "toy"
    }

    fn format(&self) -> u16 {
        FORMAT
    }

    fn define(&self, definition: &[u8]) -> Result<()> {
        if definition.first() == Some(&1) {
            Ok(())
        } else {
            Err(Error::invalid("toy definition", "unknown format"))
        }
    }

    fn apply(&self, seq: Seq, section: &Section<'_>) -> Result<()> {
        if section.format != FORMAT || section.flags != 0 {
            return Err(Error::corrupt("a toy section format", seq));
        }
        if seq <= self.applied.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut puts = Vec::new();
        let mut r = Reader::new(section.body, "a toy section", seq);
        while !r.is_empty() {
            puts.push((r.u16()?, r.u64()?));
        }
        let mut cells = self.cells.lock().unwrap_or_else(PoisonError::into_inner);
        for (key, value) in puts {
            let _ = cells.insert(key, value);
        }
        self.applied.store(seq, Ordering::Release);
        let _ = self.installs.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn durable_through(&self) -> Seq {
        self.durable.load(Ordering::Acquire)
    }

    fn checkpoint(&self) -> Result<Seq> {
        let cells = self.cells.lock().unwrap_or_else(PoisonError::into_inner);
        let through = self.applied.load(Ordering::Acquire);
        let mut bytes = Vec::new();
        let mut w = Writer::new(&mut bytes);
        w.u64(through);
        for (key, value) in cells.iter() {
            w.u16(*key);
            w.u64(*value);
        }
        fs::write_atomic(&self.file, &bytes)?;
        self.durable.store(through, Ordering::Release);
        Ok(through)
    }

    fn reclaim(&self, watermark: Seq) {
        self.conflicts.prune(watermark);
    }
}

struct ToyStaged<'e> {
    engine: &'e ToyEngine,
    collection: u32,
    puts: Vec<(u16, u64)>,
    priority: bool,
}

impl<'e> ToyStaged<'e> {
    fn new(engine: &'e ToyEngine, collection: u32) -> Self {
        ToyStaged {
            engine,
            collection,
            puts: Vec::new(),
            priority: false,
        }
    }

    fn put(mut self, key: u16, value: u64) -> Self {
        self.puts.push((key, value));
        self
    }

    fn keys(&self) -> impl Iterator<Item = [u8; 2]> + '_ {
        self.puts.iter().map(|(key, _)| key.to_le_bytes())
    }
}

impl Staged for ToyStaged<'_> {
    fn engine(&self) -> EngineId {
        self.engine.id
    }

    fn collection(&self) -> u32 {
        self.collection
    }

    fn is_empty(&self) -> bool {
        self.puts.is_empty()
    }

    fn priority(&self) -> bool {
        self.priority
    }

    fn validate(&self, snapshot: Seq) -> std::result::Result<(), Conflict> {
        let keys: Vec<[u8; 2]> = self.keys().collect();
        if self
            .engine
            .conflicts
            .conflicts(keys.iter().map(|k| &k[..]), snapshot)
        {
            Err(Conflict)
        } else {
            Ok(())
        }
    }

    fn reserve(&self, seq: Seq) {
        let keys: Vec<[u8; 2]> = self.keys().collect();
        self.engine
            .conflicts
            .record(keys.iter().map(|k| &k[..]), seq);
    }

    fn encode(&self, _seq: Seq, out: &mut Vec<u8>) -> Result<()> {
        let mut w = Writer::new(out);
        for (key, value) in &self.puts {
            w.u16(*key);
            w.u64(*value);
        }
        Ok(())
    }
}

/// Two toy engines and nothing else.
struct Toys {
    a: ToyEngine,
    b: ToyEngine,
}

const TOY_A: EngineId = EngineId(62);
const TOY_B: EngineId = EngineId(63);

impl Registry for Toys {
    fn get(&self, id: EngineId) -> Option<&dyn Engine> {
        match id {
            TOY_A => Some(&self.a),
            TOY_B => Some(&self.b),
            _ => None,
        }
    }

    fn each(&self, f: &mut dyn FnMut(&dyn Engine)) {
        f(&self.a);
        f(&self.b);
    }
}

/// The toy database. It takes no checkpoint when dropped, so every reopen
/// in these tests replays the log unless a test checkpoints on purpose.
struct Db {
    // Field order: the core (and its directory lock) drops last.
    toys: Toys,
    core: Core,
}

impl Db {
    fn open(dir: &Path) -> Result<Db> {
        let (core, new_database) = Core::open(dir)?;
        let toys = Toys {
            a: ToyEngine::open(&dir.join("toy"), TOY_A)?,
            b: ToyEngine::open(&dir.join("toy"), TOY_B)?,
        };
        core.recover(&toys, new_database, &[])?;
        Ok(Db { toys, core })
    }

    fn collection(&self, name: &str) -> u32 {
        self.core.catalog().named(name).unwrap().id
    }

    fn commit(&self, staged: &[&dyn Staged]) -> std::result::Result<(), Attempt> {
        let snapshot = self.core.snapshot();
        self.core.commit(&self.toys, snapshot.seq(), staged)
    }
}

fn temp_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "nex-db-toy-{}-{}",
        std::process::id(),
        id_forge::ulid::Ulid::new()
    ))
}

/// A database with collection "a" of toy A and "b" of toy B.
fn defined(dir: &Path) -> Db {
    let db = Db::open(dir).unwrap();
    db.core
        .define_collection(&db.toys, TOY_A, "a", DEFINITION)
        .unwrap();
    db.core
        .define_collection(&db.toys, TOY_B, "b", DEFINITION)
        .unwrap();
    db
}

/// Every record's class, in log order.
fn classes(dir: &Path) -> Vec<Class> {
    let log = CommitLog::open(&dir.join("core").join("log")).unwrap();
    let mut out = Vec::new();
    log.replay(|lsn, bytes| {
        out.push(record::decode(bytes, lsn)?.class);
        Ok(())
    })
    .unwrap();
    out
}

#[test]
fn test_toy_commit_across_two_engines_applies_both() {
    let dir = temp_dir();
    let db = defined(&dir);
    let (a, b) = (db.collection("a"), db.collection("b"));
    let one = ToyStaged::new(&db.toys.a, a).put(1, 10);
    let two = ToyStaged::new(&db.toys.b, b).put(1, 20);
    db.commit(&[&one, &two]).unwrap();
    assert_eq!(db.toys.a.get(1), Some(10));
    assert_eq!(db.toys.b.get(1), Some(20));
    assert_eq!(db.core.visible(), 3);
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_toy_reopen_without_checkpoint_replays_every_engine() {
    let dir = temp_dir();
    let db = defined(&dir);
    let (a, b) = (db.collection("a"), db.collection("b"));
    for i in 0..5u64 {
        let one = ToyStaged::new(&db.toys.a, a).put(1, i);
        let two = ToyStaged::new(&db.toys.b, b).put(2, i * 2);
        db.commit(&[&one, &two]).unwrap();
    }
    // No checkpoint was taken: the log alone must bring both back.
    drop(db);

    let db = Db::open(&dir).unwrap();
    assert_eq!(db.toys.a.get(1), Some(4));
    assert_eq!(db.toys.b.get(2), Some(8));
    assert_eq!(db.toys.a.installs.load(Ordering::Relaxed), 5);
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_toy_checkpointed_engine_skips_what_it_holds() {
    let dir = temp_dir();
    let db = defined(&dir);
    let (a, b) = (db.collection("a"), db.collection("b"));
    for i in 0..3u64 {
        let one = ToyStaged::new(&db.toys.a, a).put(1, i);
        let two = ToyStaged::new(&db.toys.b, b).put(1, i);
        db.commit(&[&one, &two]).unwrap();
    }
    let _ = db.toys.a.checkpoint().unwrap();
    drop(db);

    let db = Db::open(&dir).unwrap();
    assert_eq!(db.toys.a.installs.load(Ordering::Relaxed), 0);
    assert_eq!(db.toys.b.installs.load(Ordering::Relaxed), 3);
    assert_eq!((db.toys.a.get(1), db.toys.b.get(1)), (Some(2), Some(2)));
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_toy_concurrent_write_of_same_key_conflicts() {
    let dir = temp_dir();
    let db = defined(&dir);
    let a = db.collection("a");
    let early = db.core.snapshot();
    db.commit(&[&ToyStaged::new(&db.toys.a, a).put(7, 1)])
        .unwrap();
    let late = ToyStaged::new(&db.toys.a, a).put(7, 2);
    assert!(matches!(
        db.core.commit(&db.toys, early.seq(), &[&late]),
        Err(Attempt::Conflict)
    ));
    let other_key = ToyStaged::new(&db.toys.a, a).put(8, 2);
    db.core
        .commit(&db.toys, early.seq(), &[&other_key])
        .unwrap();
    drop(early);
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_toy_priority_part_makes_record_priority() {
    let dir = temp_dir();
    let db = defined(&dir);
    let (a, b) = (db.collection("a"), db.collection("b"));
    let plain = ToyStaged::new(&db.toys.a, a).put(1, 1);
    db.commit(&[&plain]).unwrap();
    let mut urgent = ToyStaged::new(&db.toys.b, b).put(1, 1);
    urgent.priority = true;
    let plain = ToyStaged::new(&db.toys.a, a).put(2, 1);
    db.commit(&[&plain, &urgent]).unwrap();
    drop(db);
    assert_eq!(
        classes(&dir),
        [
            Class::Durable,
            Class::Durable,
            Class::Durable,
            Class::Priority
        ]
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_toy_empty_parts_write_nothing() {
    let dir = temp_dir();
    let db = defined(&dir);
    let a = db.collection("a");
    db.commit(&[&ToyStaged::new(&db.toys.a, a)]).unwrap();
    assert_eq!(db.core.visible(), 2);
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_toy_define_checks_engine_name_and_definition() {
    let dir = temp_dir();
    let db = defined(&dir);
    assert!(matches!(
        db.core.define_collection(&db.toys, TOY_A, "c", b"\x02"),
        Err(Error::Invalid { .. })
    ));
    assert!(matches!(
        db.core.define_collection(&db.toys, TOY_B, "a", DEFINITION),
        Err(Error::AlreadyExists { what: "collection" })
    ));
    assert!(matches!(
        db.core
            .define_collection(&db.toys, EngineId(9), "c", DEFINITION),
        Err(Error::Invalid { .. })
    ));
    assert_eq!(
        db.core
            .define_collection(&db.toys, TOY_A, "c", DEFINITION)
            .unwrap(),
        3
    );
    drop(db);

    let db = Db::open(&dir).unwrap();
    let c = db.core.catalog().named("c").unwrap();
    assert_eq!((c.engine, &*c.definition), (TOY_A, DEFINITION));
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_toy_section_for_collection_of_other_engine_halts() {
    let dir = temp_dir();
    let db = defined(&dir);
    let b = db.collection("b");
    // Toy A writing into toy B's collection: refused at apply, writes stop.
    let wrong = ToyStaged::new(&db.toys.a, b).put(1, 1);
    assert!(matches!(
        db.commit(&[&wrong]),
        Err(Attempt::Failed(Error::Corrupt { .. }))
    ));
    assert!(db.core.halted());
    let a = db.collection("a");
    assert!(matches!(
        db.commit(&[&ToyStaged::new(&db.toys.a, a).put(1, 1)]),
        Err(Attempt::Failed(Error::Storage { .. }))
    ));
    drop(db);
    // The log holds the bad record, so the database stays closed.
    assert!(matches!(Db::open(&dir), Err(Error::Corrupt { .. })));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_toy_engine_ahead_of_log_refuses_open() {
    let dir = temp_dir();
    let db = defined(&dir);
    let a = db.collection("a");
    db.commit(&[&ToyStaged::new(&db.toys.a, a).put(1, 1)])
        .unwrap();
    let _ = db.toys.a.checkpoint().unwrap();
    drop(db);
    // A checkpoint claiming a commit the log never had.
    let file = dir.join("toy").join("toy-62.state");
    let mut bytes = std::fs::read(&file).unwrap();
    bytes[..8].copy_from_slice(&99u64.to_le_bytes());
    std::fs::write(&file, bytes).unwrap();
    assert!(matches!(Db::open(&dir), Err(Error::Corrupt { .. })));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_toy_unhosted_engine_in_log_keeps_database_closed() {
    let dir = temp_dir();
    let db = defined(&dir);
    let b = db.collection("b");
    db.commit(&[&ToyStaged::new(&db.toys.b, b).put(1, 1)])
        .unwrap();
    drop(db);

    // Reopen hosting only toy A: the log names an engine this build lacks.
    struct OnlyA(ToyEngine);
    impl Registry for OnlyA {
        fn get(&self, id: EngineId) -> Option<&dyn Engine> {
            (id == TOY_A).then_some(&self.0 as &dyn Engine)
        }
        fn each(&self, f: &mut dyn FnMut(&dyn Engine)) {
            f(&self.0);
        }
    }
    let (core, new_database) = Core::open(&dir).unwrap();
    let only = OnlyA(ToyEngine::open(&dir.join("toy"), TOY_A).unwrap());
    assert!(matches!(
        core.recover(&only, new_database, &[]),
        Err(Error::Corrupt { .. })
    ));
    drop(only);
    drop(core);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_toy_concurrent_commits_all_apply_in_order_and_survive_reopen() {
    let dir = temp_dir();
    let db = defined(&dir);
    let a = db.collection("a");
    const THREADS: u16 = 8;
    const EACH: u16 = 50;
    std::thread::scope(|s| {
        for t in 0..THREADS {
            let db = &db;
            s.spawn(move || {
                for i in 0..EACH {
                    let key = t * EACH + i;
                    db.commit(&[&ToyStaged::new(&db.toys.a, a).put(key, u64::from(key))])
                        .unwrap();
                }
            });
        }
    });
    let total = u64::from(THREADS * EACH);
    // Two catalog records, then one record per commit.
    assert_eq!(db.core.visible(), 2 + total);
    drop(db);

    let db = Db::open(&dir).unwrap();
    for key in 0..THREADS * EACH {
        assert_eq!(db.toys.a.get(key), Some(u64::from(key)));
    }
    assert_eq!(db.core.visible(), 2 + total);
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}
