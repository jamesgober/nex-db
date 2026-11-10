//! Backups and point-in-time restore.
//!
//! A backup directory holds a base, the database's files at one commit,
//! and an archive of the commit log from that commit on:
//!
//! ```text
//! <backup>/
//! ├─ BACKUP           the manifest
//! ├─ base/            the base: files as they were, each store as a dump
//! └─ log/             archived log records, from the base's commit on
//! ```
//!
//! The first backup into an empty directory writes the base while writes
//! wait (reads go on); every later backup into the same directory appends
//! the log records committed since, and copies the data key files again.
//! A restore rebuilds the stores from their dumps and writes the archived
//! records up to the chosen point as the new database's log; opening it
//! replays them. Revocations committed after the point (ended sessions,
//! sign-outs everywhere, blocking standings, password changes, revoked API
//! keys, erasures) are kept aside and applied again when the restored
//! database first opens, so a restore never brings back access that was
//! taken away.

use std::{
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

use crate::{
    core::{
        codec::{Reader, Writer},
        fs as nfs,
        log::CommitLog,
        pipeline::Core,
        record::{self, Class, Seq},
    },
    engine::{BackupSink, Registry},
    error::{Error, Result},
    feed::Position,
};

const MANIFEST: &str = "BACKUP";
const MAGIC: &[u8; 8] = b"NXDBBKUP";
const FORMAT: u16 = 1;
const BASE: &str = "base";
const ARCHIVE: &str = "log";
/// Records of commits after a restore point that take access away, applied
/// again when the restored database opens.
pub(crate) const REAPPLY: &str = "reapply";
/// What a manifest item is.
const ITEM_FILE: u8 = 1;
const ITEM_STORE: u8 = 2;
const ITEM_KEYS: u8 = 3;
/// Pairs written to a restored store per batch.
#[cfg(any(feature = "auth", feature = "content"))]
const RESTORE_BATCH: usize = 4096;

/// What [`Database::backup`](crate::Database::backup) did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupInfo {
    position: Position,
    base: Position,
    incremental: bool,
    holds_key: bool,
}

impl BackupInfo {
    /// The last commit the backup holds: a restore can reach it.
    #[must_use]
    pub const fn position(&self) -> Position {
        self.position
    }

    /// The commit of the backup's base: the earliest a restore can reach.
    #[must_use]
    pub const fn base(&self) -> Position {
        self.base
    }

    /// True when this call added to an existing backup.
    #[must_use]
    pub const fn incremental(&self) -> bool {
        self.incremental
    }

    /// True when the backup holds the database's root key, as it does for a
    /// database whose key lives in its own directory
    /// ([`Keys::in_directory`](crate::Keys::in_directory)): keep such a
    /// backup as safe as the key itself.
    #[must_use]
    pub const fn holds_key(&self) -> bool {
        self.holds_key
    }
}

/// How far [`restore`] replays.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestorePoint {
    /// Every commit the backup holds.
    Latest,
    /// The commits made at or before this time: up to the last one before
    /// the first commit made after it.
    At(SystemTime),
    /// The commits up to and including this one.
    Position(Position),
}

/// The manifest.
struct Manifest {
    base: Seq,
    holds_key: bool,
    items: Vec<(u8, String)>,
}

impl Manifest {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut w = Writer::new(&mut out);
        w.bytes(MAGIC);
        w.u16(FORMAT);
        w.u64(self.base);
        w.u8(u8::from(self.holds_key));
        w.u16(
            u16::try_from(self.items.len())
                .map_err(|_| Error::invalid("backup", "too many files"))?,
        );
        for (kind, path) in &self.items {
            w.u8(*kind);
            w.str16(path)?;
        }
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Manifest> {
        let corrupt = || Error::corrupt("the backup manifest", 0);
        let mut r = Reader::new(bytes, "the backup manifest", 0);
        if r.fixed::<8>()? != *MAGIC || r.u16()? != FORMAT {
            return Err(corrupt());
        }
        let base = r.u64()?;
        let holds_key = r.u8()? == 1;
        let mut items = Vec::new();
        for _ in 0..r.u16()? {
            let kind = r.u8()?;
            if !matches!(kind, ITEM_FILE | ITEM_STORE | ITEM_KEYS) {
                return Err(corrupt());
            }
            let path = r.str16()?.to_owned();
            // A path stays inside the backup and the database.
            if path.is_empty()
                || path
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == "..")
                || path.contains('\\')
                || path.contains(':')
            {
                return Err(corrupt());
            }
            items.push((kind, path));
        }
        r.finish()?;
        Ok(Manifest {
            base,
            holds_key,
            items,
        })
    }

    fn read(dir: &Path) -> Result<Option<Manifest>> {
        match nfs::read_optional(&dir.join(MANIFEST))? {
            Some(bytes) => Manifest::decode(&bytes).map(Some),
            None => Ok(None),
        }
    }
}

/// `path` under `root`, `/`-separated.
fn relative(root: &Path, path: &Path) -> Result<String> {
    let rel = path
        .strip_prefix(root)
        .map_err(|_| Error::invalid("backup", "a file outside the database"))?;
    let parts: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    Ok(parts.join("/"))
}

/// `rel` (`/`-separated) under `root`.
fn under(root: &Path, rel: &str) -> PathBuf {
    rel.split('/')
        .fold(root.to_path_buf(), |p, part| p.join(part))
}

fn io(what: &'static str) -> impl Fn(std::io::Error) -> Error {
    move |e| Error::storage(what, e)
}

/// Copy `from` to `to` and sync it; through a temporary file and a rename,
/// so `to` is the old file or the new one.
fn copy_synced(from: &Path, to: &Path) -> Result<()> {
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent).map_err(io("creating a backup directory"))?;
    }
    let tmp = to.with_extension("tmp");
    let _ = fs::copy(from, &tmp).map_err(io("copying a file"))?;
    // Windows syncs only a handle open for writing.
    fs::OpenOptions::new()
        .write(true)
        .open(&tmp)
        .and_then(|f| f.sync_all())
        .map_err(io("syncing a copied file"))?;
    fs::rename(&tmp, to).map_err(io("renaming a copied file"))?;
    if let Some(parent) = to.parent() {
        nfs::sync_names(parent)?;
    }
    Ok(())
}

/// One key and value of a store dump, as a log record.
#[cfg_attr(not(any(feature = "auth", feature = "content")), allow(dead_code))]
fn encode_pair(key: &[u8], value: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(8 + key.len() + value.len());
    let mut w = Writer::new(&mut out);
    w.bytes32(key)?;
    w.bytes32(value)?;
    Ok(out)
}

/// Writes the base of a first backup, or the key files of a later one.
pub(crate) struct Sink<'a> {
    root: &'a Path,
    base: PathBuf,
    items: Vec<(u8, String)>,
    /// A later backup: only key files are copied.
    keys_only: bool,
}

#[cfg(feature = "split-auth")]
impl<'a> Sink<'a> {
    /// A sink for the auth process, which writes its engines' files into
    /// the backup the application takes.
    pub(crate) fn new(root: &'a Path, base: PathBuf, keys_only: bool) -> Self {
        Sink {
            root,
            base,
            items: Vec::new(),
            keys_only,
        }
    }

    /// What it wrote, for the application's manifest.
    pub(crate) fn into_items(self) -> Vec<(u8, String)> {
        self.items
    }
}

impl BackupSink for Sink<'_> {
    fn target(&self) -> (&Path, &Path, bool) {
        (self.root, &self.base, self.keys_only)
    }

    fn merge(&mut self, items: Vec<(u8, String)>) -> Result<()> {
        for (kind, rel) in items {
            if !matches!(kind, ITEM_FILE | ITEM_STORE | ITEM_KEYS) {
                return Err(Error::corrupt("a backup item from the auth process", 0));
            }
            if !self.items.iter().any(|(_, r)| *r == rel) {
                self.items.push((kind, rel));
            }
        }
        Ok(())
    }

    fn file(&mut self, path: &Path) -> Result<()> {
        if self.keys_only || !path.exists() {
            return Ok(());
        }
        let rel = relative(self.root, path)?;
        copy_synced(path, &under(&self.base, &rel))?;
        self.items.push((ITEM_FILE, rel));
        Ok(())
    }

    fn keys(&mut self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }
        let rel = relative(self.root, path)?;
        copy_synced(path, &under(&self.base, &rel))?;
        if !self.items.iter().any(|(_, r)| *r == rel) {
            self.items.push((ITEM_KEYS, rel));
        }
        Ok(())
    }

    fn store(
        &mut self,
        dir: &Path,
        pairs: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
    ) -> Result<()> {
        if self.keys_only {
            return Ok(());
        }
        let rel = relative(self.root, dir)?;
        let dump = CommitLog::open(&under(&self.base, &format!("{rel}.dump")))?;
        for (key, value) in pairs {
            dump.append(&encode_pair(&key, &value)?)?;
        }
        dump.sync()?;
        self.items.push((ITEM_STORE, rel));
        Ok(())
    }
}

/// The sequence number of a log record (it follows the two-byte format).
fn seq_of(bytes: &[u8], at: u64) -> Result<Seq> {
    bytes
        .get(2..10)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_le_bytes)
        .ok_or(Error::corrupt("a log record", at))
}

/// The last record of `log`: its sequence number and bytes.
fn last_record(log: &CommitLog) -> Result<Option<(Seq, Vec<u8>)>> {
    let mut last = None;
    log.replay(|at, bytes| {
        last = Some((seq_of(bytes, at)?, bytes.to_vec()));
        Ok(())
    })?;
    Ok(last)
}

/// Back up the database (its directory `root`) into `to`; see
/// [`Database::backup`](crate::Database::backup).
pub(crate) fn backup(
    core: &Core,
    engines: &dyn Registry,
    root: &Path,
    to: &Path,
) -> Result<BackupInfo> {
    let existing = Manifest::read(to)?;
    if existing.is_none()
        && to.exists()
        && fs::read_dir(to)
            .map_err(io("reading the backup directory"))?
            .next()
            .is_some()
    {
        return Err(Error::invalid(
            "backup directory",
            "not empty and not a backup",
        ));
    }
    let frozen = core.freeze()?;
    let last = frozen.last();
    let key_check = root.join("auth").join(crate::core::keys::CHECK_FILE);
    match existing {
        None => {
            fs::create_dir_all(to).map_err(io("creating the backup directory"))?;
            frozen.checkpoint(engines)?;
            let mut sink = Sink {
                root,
                base: to.join(BASE),
                items: Vec::new(),
                keys_only: false,
            };
            sink.file(&root.join("core").join(crate::core::catalog::CHECKPOINT))?;
            sink.file(&key_check)?;
            let key = root.join("auth").join(crate::core::keys::KEY_FILE);
            let holds_key = key.exists();
            if engines.copies_root_key() {
                sink.file(&key)?;
            }
            let mut failed = None;
            engines.each(&mut |engine| {
                if failed.is_none() {
                    failed = engine.backup(&mut sink).err();
                }
            });
            if let Some(err) = failed {
                return Err(err);
            }
            // The archive starts at the base's own record: a log always
            // holds the record at the lowest mark of the stores.
            let archive = CommitLog::open(&to.join(ARCHIVE))?;
            frozen.records(|at, bytes| {
                if seq_of(bytes, at)? == last {
                    archive.append(bytes)?;
                }
                Ok(())
            })?;
            archive.sync()?;
            let manifest = Manifest {
                base: last,
                holds_key,
                items: sink.items,
            };
            nfs::write_atomic(&to.join(MANIFEST), &manifest.encode()?)?;
            Ok(BackupInfo {
                position: Position(last),
                base: Position(last),
                incremental: false,
                holds_key,
            })
        }
        Some(manifest) => {
            let theirs = nfs::read_optional(&under(&to.join(BASE), "auth/key.check"))?;
            let ours = nfs::read_optional(&key_check)?;
            if theirs != ours {
                return Err(Error::invalid(
                    "backup directory",
                    "a backup of another database",
                ));
            }
            let archive = CommitLog::open(&to.join(ARCHIVE))?;
            let (archived, bytes) =
                last_record(&archive)?.ok_or_else(|| Error::corrupt("the backup log", 0))?;
            // The live log must still hold the archive's last record, the
            // same bytes, so nothing between them is missing.
            let mut found = false;
            let mut appended = 0u64;
            frozen.records(|at, record| {
                let seq = seq_of(record, at)?;
                if seq == archived {
                    if record != bytes.as_slice() {
                        return Err(Error::invalid(
                            "backup directory",
                            "a backup of another database",
                        ));
                    }
                    found = true;
                } else if seq > archived && found {
                    archive.append(record)?;
                    appended += 1;
                }
                Ok(())
            })?;
            if !found {
                return Err(Error::invalid(
                    "backup directory",
                    "the log no longer holds the commits after this backup: back up into a new directory",
                ));
            }
            archive.sync()?;
            let mut sink = Sink {
                root,
                base: to.join(BASE),
                items: manifest.items,
                keys_only: true,
            };
            let mut failed = None;
            engines.each(&mut |engine| {
                if failed.is_none() {
                    failed = engine.backup(&mut sink).err();
                }
            });
            if let Some(err) = failed {
                return Err(err);
            }
            let next = Manifest {
                base: manifest.base,
                holds_key: manifest.holds_key,
                items: sink.items,
            };
            nfs::write_atomic(&to.join(MANIFEST), &next.encode()?)?;
            let _ = appended;
            Ok(BackupInfo {
                position: Position(last.max(archived)),
                base: Position(manifest.base),
                incremental: true,
                holds_key: manifest.holds_key,
            })
        }
    }
}

/// Restore the backup in `backup` into the new directory `into`, up to
/// `point`, and return the position of the last commit restored.
///
/// The restored database opens with the key source of the database backed
/// up (the backup holds the key only for one whose key lives in its own
/// directory). When it opens, the revocations committed after `point` are
/// applied again in one commit.
///
/// ```no_run
/// # fn main() -> nex_db::Result<()> {
/// use nex_db::RestorePoint;
/// let db = nex_db::open("data/site")?;
/// let info = db.backup("backups/site")?;
/// drop(db);
/// let at = nex_db::restore("backups/site", "data/site-restored", RestorePoint::Latest)?;
/// assert_eq!(at, info.position());
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// - [`Error::Invalid`] when `backup` holds no backup, `into` is not empty,
///   or `point` is before the backup's base or after its last commit.
/// - [`Error::Corrupt`] when the backup fails its checks.
/// - [`Error::Storage`] when a file cannot be read or written.
pub fn restore(
    backup: impl AsRef<Path>,
    into: impl AsRef<Path>,
    point: RestorePoint,
) -> Result<Position> {
    let (backup, into) = (backup.as_ref(), into.as_ref());
    let manifest =
        Manifest::read(backup)?.ok_or_else(|| Error::invalid("backup", "no backup here"))?;
    if into.exists()
        && fs::read_dir(into)
            .map_err(io("reading the restore directory"))?
            .next()
            .is_some()
    {
        return Err(Error::invalid("restore directory", "not empty"));
    }
    // Every archived record: its sequence number, time, and class.
    let archive = CommitLog::open(&backup.join(ARCHIVE))?;
    let mut records: Vec<(Seq, u64, Class)> = Vec::new();
    archive.replay(|at, bytes| {
        let view = record::decode(bytes, at)?;
        if let Some((seq, _, _)) = records.last() {
            if view.seq != seq + 1 {
                return Err(Error::corrupt("the backup log sequence", view.seq));
            }
        } else if view.seq != manifest.base {
            return Err(Error::corrupt("the backup log start", view.seq));
        }
        records.push((view.seq, view.time_ms, view.class));
        Ok(())
    })?;
    let last = records
        .last()
        .map(|(s, _, _)| *s)
        .ok_or_else(|| Error::corrupt("the backup log", 0))?;
    let target = match point {
        RestorePoint::Latest => last,
        RestorePoint::Position(Position(p)) => {
            if p < manifest.base || p > last {
                return Err(Error::invalid(
                    "restore point",
                    "outside the commits the backup holds",
                ));
            }
            p
        }
        RestorePoint::At(time) => {
            let ms = time
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
            let before = records.iter().take_while(|(_, t, _)| *t <= ms).last();
            match before {
                Some((seq, _, _)) => *seq,
                None => {
                    return Err(Error::invalid("restore point", "before the backup's base"));
                }
            }
        }
    };
    fs::create_dir_all(into).map_err(io("creating the restore directory"))?;
    let base = backup.join(BASE);
    for (kind, rel) in &manifest.items {
        match *kind {
            ITEM_STORE => restore_store(&under(&base, &format!("{rel}.dump")), &under(into, rel))?,
            _ => copy_synced(&under(&base, rel), &under(into, rel))?,
        }
    }
    let log = CommitLog::open(&into.join("core").join("log"))?;
    let reapply_dir = into.join("core").join(REAPPLY);
    let mut reapply: Option<CommitLog> = None;
    archive.replay(|at, bytes| {
        let seq = seq_of(bytes, at)?;
        if seq <= target {
            log.append(bytes)?;
        } else if record::decode(bytes, at)?.class == Class::Priority {
            if reapply.is_none() {
                reapply = Some(CommitLog::open(&reapply_dir)?);
            }
            if let Some(r) = &reapply {
                r.append(bytes)?;
            }
        }
        Ok(())
    })?;
    log.sync()?;
    if let Some(r) = &reapply {
        r.sync()?;
    }
    nfs::sync_names(&into.join("core"))?;
    nfs::sync_names(into)?;
    Ok(Position(target))
}

/// Apply again the revocations a restore kept aside, in one commit, then
/// drop them. Called when a database opens, after recovery.
pub(crate) fn reapply(db: &crate::Database) -> Result<()> {
    let core_dir = db.path().join("core");
    let dir = core_dir.join(REAPPLY);
    if !dir.exists() {
        return Ok(());
    }
    let mut records = Vec::new();
    {
        let log = CommitLog::open(&dir)?;
        log.replay(|_, bytes| {
            records.push(bytes.to_vec());
            Ok(())
        })?;
    }
    reapply_records(db, &records)?;
    fs::remove_dir_all(&dir).map_err(io("removing the revocations applied again"))?;
    nfs::sync_names(&core_dir)
}

#[cfg(feature = "auth")]
fn reapply_records(db: &crate::Database, records: &[Vec<u8>]) -> Result<()> {
    use crate::engine::EngineId;
    db.commit(|tx| {
        for (at, bytes) in records.iter().enumerate() {
            let view = record::decode(bytes, at as u64)?;
            for section in &view.sections {
                // A realm defined after the restore point is not there.
                if section.engine == EngineId::AUTH
                    && db.catalog_binds(section.collection, EngineId::AUTH)
                {
                    tx.auth_of(section.collection).reapply(view.seq, section)?;
                }
            }
        }
        Ok(())
    })
}

#[cfg(not(feature = "auth"))]
fn reapply_records(_db: &crate::Database, records: &[Vec<u8>]) -> Result<()> {
    if records.is_empty() {
        return Ok(());
    }
    Err(Error::invalid(
        "restored database",
        "holds revocations to apply again, and this build has no auth engine",
    ))
}

/// Rebuild the store in `dir` from the dump in `dump`.
#[cfg(any(feature = "auth", feature = "content"))]
fn restore_store(dump: &Path, dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).map_err(io("creating a restored store"))?;
    let store = lsm_db::Lsm::open(dir)?;
    let log = CommitLog::open(dump)?;
    let mut batch = lsm_db::Batch::new();
    let mut failed = None;
    log.replay(|at, bytes| {
        let mut r = Reader::new(bytes, "a store dump record", at);
        let key = r.bytes32()?;
        let value = r.bytes32()?;
        r.finish()?;
        batch.put(key, value);
        if batch.len() >= RESTORE_BATCH {
            if let Err(err) = store.write(std::mem::take(&mut batch)) {
                failed = Some(Error::from(err));
            }
        }
        Ok(())
    })?;
    if let Some(err) = failed {
        return Err(err);
    }
    if !batch.is_empty() {
        store.write(batch)?;
    }
    store.flush()?;
    Ok(())
}

#[cfg(not(any(feature = "auth", feature = "content")))]
fn restore_store(_dump: &Path, _dir: &Path) -> Result<()> {
    Err(Error::invalid(
        "backup",
        "holds a store, and this build has no engine to read it",
    ))
}

/// Runs this module's decoders on `data`, for fuzzing and tests. Errors are
/// expected; a panic, a hang, or an allocation the input asked for is a bug.
#[cfg(any(fuzzing, test))]
pub(crate) fn fuzz(data: &[u8]) {
    let _ = Manifest::decode(data);
}
