//! The engine contract.
//!
//! nex-db is one core with several engines on it. The core owns the commit
//! log, the sequence numbers, the catalog, snapshots, and recovery; an engine
//! owns one shape of data (auth: sessions and accounts; content: entities and
//! routes) and its own files. They meet only through the two traits here:
//!
//! - [`Engine`]: implemented once per engine. The core calls it to check a
//!   collection definition, to install committed work ([`Engine::apply`]),
//!   and to manage the engine's own files (durable mark, checkpoint,
//!   reclaim).
//! - [`Staged`]: one transaction's work in one engine. The engine's typed
//!   operations write into it; the core validates it against concurrent
//!   commits, reserves its keys, and encodes it into the engine's section of
//!   the log record.
//!
//! A commit runs: validate every [`Staged`], take the next sequence number,
//! encode each one as a section of one log record, append and sync the
//! record, reserve, then decode the record and call [`Engine::apply`] for each
//! section, and only then make the commit visible. Recovery decodes the same
//! records and calls the same `apply`. A replica (later) does the same again.
//! There is no second way to change an engine's state.
//!
//! # Rules every engine follows
//!
//! | Rule | Why |
//! |---|---|
//! | state changes only in `apply` | commit, recovery, and replicas share one code path |
//! | `apply` is deterministic: no clock, no randomness, no I/O outside the engine's own files | a replay reaches the same state; times and ids are chosen while staging and carried in the section |
//! | `apply` is idempotent by sequence number | a crash in the middle of apply is followed by a replay of the same record |
//! | an engine never reads another engine's data | the auth engine stays sealed; cross-engine work is composed by the caller in one commit |
//! | sections carry a format number; old formats stay readable | an engine can change its encoding without rewriting the log |
//!
//! # What the core guarantees an engine
//!
//! - `apply` is called in sequence order, from one thread at a time, with a
//!   section that passed the record checks (engine mask, lengths, flags) and
//!   whose collection the catalog binds to this engine.
//! - [`Staged::validate`], [`Staged::reserve`], and [`Staged::encode`] run
//!   inside the commit lock, in that order, with nothing in between from
//!   another commit.
//! - An engine is never handed a section of another engine.
//!
//! # Adding an engine
//!
//! Pick a free id, implement both traits, host the engine in the database
//! facade behind a feature, and add its typed operations. The commit
//! pipeline, recovery, and the catalog need no change: the toy engine in this
//! module's tests runs on the core with no other engine present.
//!
//! The contract is crate-internal: engines are modules of this crate, so the
//! contract can change between versions without breaking callers.

use crate::{
    core::record::{Section, Seq},
    error::{Error, Result},
};

#[cfg(test)]
mod toy;

/// A fixed engine id. Never reused. Ids 0 to 127 fit the log record's engine
/// mask.
///
/// | Id | Engine |
/// |---|---|
/// | 0 | the catalog (core) |
/// | 1 | auth |
/// | 2 | content |
/// | 3, 4, 5 | reserved for the log, blob, and hot engines |
/// | 6 to 63 | reserved for later engines of this crate |
/// | 64 to 127 | reserved |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct EngineId(pub(crate) u16);

impl EngineId {
    /// The core: catalog and markers.
    pub(crate) const CATALOG: EngineId = EngineId(0);
    /// The auth engine.
    pub(crate) const AUTH: EngineId = EngineId(1);
    /// The content engine.
    pub(crate) const CONTENT: EngineId = EngineId(2);

    /// The error for a section or collection of an engine this build does not
    /// host. A known engine left out by a feature is a configuration problem;
    /// an unknown id is damage.
    pub(crate) fn missing(self) -> Error {
        match self {
            EngineId::AUTH => Error::invalid(
                "database",
                "uses the auth engine, which this build does not include",
            ),
            EngineId::CONTENT => Error::invalid(
                "database",
                "uses the content engine, which this build does not include",
            ),
            _ => Error::corrupt("a log section (engine)", u64::from(self.0)),
        }
    }
}

/// A commit lost to a concurrent commit: a key it writes was committed after
/// its snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Conflict;

/// Implemented once per engine.
pub(crate) trait Engine: Send + Sync {
    /// The engine's fixed id.
    fn id(&self) -> EngineId;

    /// The engine's name, for errors and diagnostics.
    #[allow(dead_code)]
    fn name(&self) -> &'static str;

    /// The section format version this engine writes.
    fn format(&self) -> u16;

    /// Check the definition of a new collection of this engine before the
    /// catalog records it. The catalog stores the bytes as they are; the
    /// engine owns their meaning. Called while staging, never during replay.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the definition is not one this engine accepts.
    fn define(&self, definition: &[u8]) -> Result<()>;

    /// Install a committed section at `seq`. The section carries its
    /// collection, format, flags, and body. Deterministic and idempotent: a
    /// section at or below what the engine already holds is skipped.
    ///
    /// # Errors
    ///
    /// [`Error::Corrupt`] when the section cannot be decoded, and
    /// [`Error::Storage`] when the engine's own files refuse the change. Any
    /// error halts the database's writes.
    fn apply(&self, seq: Seq, section: &Section<'_>) -> Result<()>;

    /// The highest sequence number this engine's own files hold. Recovery
    /// replays the log from just above the lowest mark of all engines.
    fn durable_through(&self) -> Seq;

    /// Make the engine's own files hold everything through `upto` and
    /// return the new durable mark (`upto`, or more). Every commit at or
    /// below `upto` has been applied when this is called; commits above it
    /// may be applying at the same time, and a checkpoint that includes some
    /// of them is fine, since `apply` is idempotent. The log is truncated
    /// below the lowest mark of all engines, so a mark must hold after a
    /// crash: the engine's files are synced before it returns.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] when a write fails. The log still holds every
    /// commit, so a failed checkpoint only means the log is not truncated.
    fn checkpoint(&self, upto: Seq) -> Result<Seq>;

    /// No running transaction has a snapshot below `watermark`: state kept
    /// only for older snapshots (conflict entries, old versions) may go.
    fn reclaim(&self, watermark: Seq);
}

/// One transaction's work in one engine.
pub(crate) trait Staged {
    /// The engine this work belongs to.
    fn engine(&self) -> EngineId;

    /// The collection this work belongs to.
    fn collection(&self) -> u32;

    /// True when the transaction staged nothing here; such an engine gets no
    /// section.
    fn is_empty(&self) -> bool;

    /// True when the work must take effect ahead of ordinary commits (a
    /// revocation). One such part makes the whole record priority class.
    fn priority(&self) -> bool {
        false
    }

    /// True when [`encode`](Self::encode) writes an encrypted body: the
    /// section is then marked sealed in the log.
    fn sealed(&self) -> bool {
        false
    }

    /// Snapshot-isolation check: fail when a key this work writes was
    /// committed after `snapshot`.
    fn validate(&self, snapshot: Seq) -> std::result::Result<(), Conflict>;

    /// Record that the staged keys are written at `seq`.
    fn reserve(&self, seq: Seq);

    /// Append the section body for the log.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when a staged value cannot be encoded (too long).
    /// The commit is refused before anything is written.
    fn encode(&self, seq: Seq, out: &mut Vec<u8>) -> Result<()>;
}

/// The engines a database hosts, apart from the catalog, which the core
/// holds itself. The database facade implements it over its typed engine
/// fields, so looking an engine up allocates nothing.
pub(crate) trait Registry {
    /// The engine with `id`, when this build hosts it.
    fn get(&self, id: EngineId) -> Option<&dyn Engine>;

    /// Call `f` with every hosted engine, in id order.
    fn each(&self, f: &mut dyn FnMut(&dyn Engine));
}
