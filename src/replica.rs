//! Read replicas: a copy of a database that follows its primary's log.
//!
//! The primary writes its commits after a position as a *shipment*
//! ([`Database::ship`]); a replica reads a shipment and commits the records
//! in it, in order, through the same path a commit takes after it is
//! encoded ([`Replica::receive`]). The bytes go through whatever the
//! application carries them over: a pipe, a socket, a file.
//!
//! A shipment is sealed end to end: every frame is encrypted and
//! authenticated (XChaCha20-Poly1305) under a key both databases derive from
//! their root key, so a replica refuses a frame that was changed, dropped
//! in the middle, reordered, or taken from another shipment, and the
//! transport learns nothing it carries. Its layout:
//!
//! ```text
//! preamble  magic "NXDBSHIP" | version u16 | shipment id [16]
//! frame     length u32 | nonce [24] | ciphertext | tag [16]
//! ```
//!
//! Frame 0 holds the position the shipment continues from and a BLAKE3
//! hash of the primary's record at that position; the replica checks it
//! against its own last record, so it only ever extends the same history.
//! Every later frame holds one commit record. The authenticated data of a
//! frame is the preamble and the frame's number.

use std::{
    io::{Read, Write},
    path::Path,
    sync::{Arc, Mutex, PoisonError},
};

use crate::{
    Database,
    core::{
        codec::{Reader, Writer},
        log::MAX_RECORD,
        record::Seq,
    },
    error::{Error, Result},
    feed::{Feed, Position},
    observe::Health,
};
use crypt_io::{Crypt, Zeroizing};

const MAGIC: &[u8; 8] = b"NXDBSHIP";
const VERSION: u16 = 1;
/// Magic, version, shipment id.
const PREAMBLE: usize = 8 + 2 + 16;
/// Nonce and tag around each frame's plaintext.
const SEAL: usize = 24 + 16;
/// Records a shipment holds at most, in bytes: a replica far behind takes
/// several shipments.
pub(crate) const SHIPMENT_BYTES: usize = 16 * 1024 * 1024;
/// The label the shipment key is derived from the root key with.
pub(crate) const KEY_LABEL: &[u8] = b"nex-db replication stream v1";
const HEAD: &str = "a shipment";

fn hash(record: &[u8]) -> [u8; 32] {
    crypt_io::hash::blake3(record)
}

fn aad(preamble: &[u8; PREAMBLE], frame: u64) -> [u8; PREAMBLE + 8] {
    let mut aad = [0u8; PREAMBLE + 8];
    aad[..PREAMBLE].copy_from_slice(preamble);
    aad[PREAMBLE..].copy_from_slice(&frame.to_le_bytes());
    aad
}

fn io(what: &'static str) -> impl Fn(std::io::Error) -> Error {
    move |e| Error::storage(what, e)
}

fn key_of(db: &Database) -> Result<&[u8; 32]> {
    db.ship_key().ok_or(Error::invalid(
        "replication",
        "needs the root key in this process (not with split auth)",
    ))
}

/// Write the commits after `after` to `out` as one shipment, and return
/// the position of the last commit in it (`after` itself when there is
/// nothing new).
pub(crate) fn ship(db: &Database, after: Position, out: &mut dyn Write) -> Result<Position> {
    let key = key_of(db)?;
    let records = db.core().shipment(after.0, SHIPMENT_BYTES)?;
    let (_, first) = records
        .first()
        .ok_or(Error::ReplicaBehind { oldest: after.0 })?;
    let mut preamble = [0u8; PREAMBLE];
    preamble[..8].copy_from_slice(MAGIC);
    preamble[8..10].copy_from_slice(&VERSION.to_le_bytes());
    let id = crypt_io::generate_key().map_err(|e| Error::storage("drawing random bytes", e))?;
    preamble[10..].copy_from_slice(&id[..16]);
    out.write_all(&preamble).map_err(io("writing a shipment"))?;

    let count = u32::try_from(records.len() - 1)
        .map_err(|_| Error::invalid("shipment", "too many records"))?;
    let mut head = Vec::with_capacity(44);
    {
        let mut w = Writer::new(&mut head);
        w.u64(after.0);
        w.bytes(&hash(first));
        w.u32(count);
    }
    let mut frame = |index: u64, plain: &[u8]| -> Result<()> {
        let sealed = Crypt::xchacha20_poly1305()
            .encrypt_with_aad(&key[..], plain, &aad(&preamble, index))
            .map_err(|e| Error::storage("sealing a shipment", e))?;
        let len = u32::try_from(sealed.len())
            .map_err(|_| Error::invalid("shipment", "a record too large"))?;
        out.write_all(&len.to_le_bytes())
            .and_then(|()| out.write_all(&sealed))
            .map_err(io("writing a shipment"))
    };
    frame(0, &head)?;
    let mut last = after.0;
    for (index, (seq, record)) in records.iter().enumerate().skip(1) {
        frame(index as u64, record)?;
        last = *seq;
    }
    out.flush().map_err(io("writing a shipment"))?;
    Ok(Position(last))
}

/// A read replica: a database that follows another's log and serves reads.
///
/// Open one with [`open_replica`] on a directory restored from a backup of
/// the primary ([`restore`](crate::restore) with
/// [`RestorePoint::Latest`](crate::RestorePoint::Latest)), under the
/// primary's key source. Then pass it what [`Database::ship`] writes:
///
/// ```no_run
/// # fn main() -> nex_db::Result<()> {
/// use nex_db::RestorePoint;
///
/// // On the primary: a backup to seed the replica.
/// let primary = nex_db::open("data/site")?;
/// primary.backup("backups/site")?;
///
/// // On the replica's machine: restore it once, then follow.
/// nex_db::restore("backups/site", "data/replica", RestorePoint::Latest)?;
/// let replica = nex_db::open_replica("data/replica")?;
///
/// // Each round: the replica's position goes to the primary, the shipment
/// // comes back (here through a buffer; in practice a socket or a pipe).
/// let mut shipment = Vec::new();
/// primary.ship(replica.position(), &mut shipment)?;
/// let at = replica.receive(&mut shipment.as_slice())?;
/// assert_eq!(at, primary.position());
/// # Ok(())
/// # }
/// ```
///
/// Its reads are the database's: [`auth`](Replica::auth),
/// [`content`](Replica::content), [`read`](Replica::read), and
/// [`feed`](Replica::feed). Every write fails with
/// [`Error::ReadOnlyReplica`]. A replica's directory is a complete
/// database: to promote it after losing the primary, drop the replica and
/// open the directory with [`open`](crate::open).
pub struct Replica {
    db: Database,
    /// The last record held: its sequence number and hash. Taken while
    /// receiving, so one shipment applies at a time.
    last: Mutex<(Seq, [u8; 32])>,
}

impl std::fmt::Debug for Replica {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Replica")
            .field("dir", &self.db.path())
            .field("position", &self.db.position())
            .finish_non_exhaustive()
    }
}

impl Replica {
    pub(crate) fn new(db: Database) -> Result<Replica> {
        let _ = key_of(&db)?;
        let (seq, record) = db.core().last_record()?.ok_or(Error::invalid(
            "replica",
            "start from a restored backup of the primary",
        ))?;
        Ok(Replica {
            db,
            last: Mutex::new((seq, hash(&record))),
        })
    }

    /// Commit the records of one shipment from `from`, and return the
    /// position reached. Records the replica already holds are skipped, so
    /// receiving a shipment twice is harmless. A shipment cut short commits
    /// the records that arrived whole.
    ///
    /// # Errors
    ///
    /// - [`Error::Invalid`] when the shipment does not continue this
    ///   replica: it is from another database (or under another key),
    ///   continues from another position, or does not start where this
    ///   replica's history does.
    /// - [`Error::Corrupt`] when a frame fails its seal or does not decode.
    /// - [`Error::Storage`] when reading `from`, or writing the replica's
    ///   log, fails.
    pub fn receive(&self, from: &mut impl Read) -> Result<Position> {
        let key = key_of(&self.db)?;
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        let mut frames = Frames::open(from, key)?;
        let (after, first, count) = frames.head()?;
        if after != last.0 {
            return Err(Error::invalid(
                "shipment",
                "it continues from another position than this replica's",
            ));
        }
        if first != last.1 {
            return Err(Error::invalid(
                "shipment",
                "its history differs from this replica's: another database",
            ));
        }
        let mut batch: Vec<Arc<[u8]>> = Vec::new();
        let mut bytes = 0;
        let mut taken = 0u32;
        while taken < count {
            let Some(record) = frames.next()? else {
                break;
            };
            taken += 1;
            bytes += record.len();
            batch.push(Arc::from(record.as_slice()));
            if bytes >= SHIPMENT_BYTES / 4 {
                self.commit(&mut last, std::mem::take(&mut batch))?;
                bytes = 0;
            }
        }
        self.commit(&mut last, batch)?;
        Ok(Position(last.0))
    }

    fn commit(&self, last: &mut (Seq, [u8; 32]), batch: Vec<Arc<[u8]>>) -> Result<()> {
        let Some(tail) = batch.last().map(|r| hash(r)) else {
            return Ok(());
        };
        match self.db.receive(batch) {
            Ok(seq) => {
                *last = (seq, tail);
                Ok(())
            }
            Err(err) => {
                // Some records may have committed before the failure: take
                // the last one from the log again.
                if let Ok(Some((seq, record))) = self.db.core().last_record() {
                    *last = (seq, hash(&record));
                }
                Err(err)
            }
        }
    }

    /// The position of the last commit the replica holds: what to ship
    /// after next.
    #[must_use]
    pub fn position(&self) -> Position {
        self.db.position()
    }

    /// Auth reads, as on the primary. Writes fail with
    /// [`Error::ReadOnlyReplica`].
    #[cfg(feature = "auth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "auth")))]
    #[must_use]
    pub fn auth(&self) -> crate::Auth<'_> {
        self.db.auth()
    }

    /// Content reads, as on the primary. Writes fail with
    /// [`Error::ReadOnlyReplica`].
    #[cfg(feature = "content")]
    #[cfg_attr(docsrs, doc(cfg(feature = "content")))]
    #[must_use]
    pub fn content(&self) -> crate::Content<'_> {
        self.db.content()
    }

    /// Read several things at one snapshot. See [`Database::read`].
    ///
    /// # Errors
    ///
    /// As [`Database::read`].
    pub fn read<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&crate::Read<'_>) -> Result<T>,
    {
        self.db.read(f)
    }

    /// The changes committed after `from`, as on the primary (the replica's
    /// own commits are the primary's). See [`Database::feed`].
    ///
    /// # Errors
    ///
    /// As [`Database::feed`].
    pub fn feed(&self, from: Position) -> Result<Feed<'_>> {
        self.db.feed(from)
    }

    /// Whether the replica can follow: [`Health::ReadOnly`] after a failed
    /// write to its own log.
    #[must_use]
    pub fn health(&self) -> Health {
        self.db.health()
    }

    /// The replica's directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.db.path()
    }
}

/// The frames of one shipment, opened one at a time.
struct Frames<'a, R: Read + ?Sized> {
    from: &'a mut R,
    key: &'a [u8; 32],
    preamble: [u8; PREAMBLE],
    index: u64,
}

impl<'a, R: Read + ?Sized> Frames<'a, R> {
    /// Read and check the preamble.
    fn open(from: &'a mut R, key: &'a [u8; 32]) -> Result<Self> {
        let mut preamble = [0u8; PREAMBLE];
        if read_full(from, &mut preamble)? < PREAMBLE {
            return Err(Error::invalid("shipment", "too short"));
        }
        if &preamble[..8] != MAGIC || preamble[8..10] != VERSION.to_le_bytes() {
            return Err(Error::invalid("shipment", "not a shipment of this version"));
        }
        Ok(Frames {
            from,
            key,
            preamble,
            index: 0,
        })
    }

    /// The next frame's plaintext; `None` at the end of the input, or where
    /// it was cut inside a frame (what came before was whole).
    fn next(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let mut len = [0u8; 4];
        if read_full(self.from, &mut len)? < 4 {
            return Ok(None);
        }
        let len = u32::from_le_bytes(len) as usize;
        if !(SEAL..=MAX_RECORD + SEAL).contains(&len) {
            return Err(Error::corrupt(HEAD, self.index));
        }
        // Grown as the bytes arrive: a length that claims more than the
        // input holds allocates no more than the input.
        let mut sealed = Vec::with_capacity(len.min(64 * 1024));
        let _ = (&mut *self.from)
            .take(len as u64)
            .read_to_end(&mut sealed)
            .map_err(io("reading a shipment"))?;
        if sealed.len() < len {
            return Ok(None);
        }
        let index = self.index;
        let plain = Crypt::xchacha20_poly1305()
            .decrypt_with_aad(&self.key[..], &sealed, &aad(&self.preamble, index))
            .map_err(|_| {
                if index == 0 {
                    Error::invalid("shipment", "sealed under another key: another database")
                } else {
                    Error::corrupt(HEAD, index)
                }
            })?;
        self.index += 1;
        Ok(Some(Zeroizing::new(plain)))
    }

    /// Frame 0: the position the shipment continues from, the hash of the
    /// record there, and how many records follow.
    fn head(&mut self) -> Result<(Seq, [u8; 32], u32)> {
        let head = self.next()?.ok_or(Error::corrupt(HEAD, 0))?;
        let mut r = Reader::new(&head[..], HEAD, 0);
        let after = r.u64()?;
        let first: [u8; 32] = r.fixed()?;
        let count = r.u32()?;
        r.finish()?;
        Ok((after, first, count))
    }
}

/// The shipment reader, for fuzzing and tests: arbitrary bytes under a
/// fixed key. Errors are expected; a panic, a hang, or an allocation the
/// input did not justify is a bug.
#[cfg(any(fuzzing, test))]
pub(crate) fn fuzz(data: &[u8]) {
    let key = [7u8; 32];
    let mut input = data;
    let Ok(mut frames) = Frames::open(&mut input, &key) else {
        return;
    };
    if frames.head().is_err() {
        return;
    }
    while let Ok(Some(_)) = frames.next() {}
}

/// Read into `buf` until it is full or the input ends; how many bytes came.
fn read_full(from: &mut (impl Read + ?Sized), buf: &mut [u8]) -> Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match from.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::storage("reading a shipment", e)),
        }
    }
    Ok(got)
}

/// Open the read replica in `path`, under the default key source. See
/// [`Replica`] and [`Builder::open_replica`](crate::Builder::open_replica).
///
/// # Errors
///
/// - [`Error::Invalid`] when `path` holds no database (a replica starts
///   from a restored backup of its primary), or one with revocations still
///   to apply again from a restore to an earlier point.
/// - As [`open`](crate::open).
pub fn open_replica(path: impl AsRef<Path>) -> Result<Replica> {
    Database::builder(path).open_replica()
}
