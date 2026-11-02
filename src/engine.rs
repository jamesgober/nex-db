//! The engine contract.
//!
//! Every engine (the catalog, auth, content, later ones) implements
//! [`Engine`]; one transaction's work in one engine is a [`Staged`]. The core
//! drives both: it validates and encodes the staged work, writes one log
//! record, then calls [`Engine::apply`] with the encoded section. `apply` is
//! the only way an engine's state changes, after a commit, during recovery,
//! and (later) on replicas, so all three take the same code path.
//!
//! Rules every engine follows:
//!
//! - `apply` is deterministic: times and ids are chosen at stage time and
//!   carried in the section, so a replay reaches the same state.
//! - `apply` is idempotent by sequence number: a section the engine already
//!   holds durably is skipped.
//! - An engine never reads another engine's data.
//!
//! The contract is internal in this version. It is documented and made public
//! with the design lock, together with a third engine in the tests.

use crate::{core::record::Seq, error::Result};

/// A fixed engine id. Never reused. Ids 0 to 127 fit the log record's engine
/// mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct EngineId(pub(crate) u16);

impl EngineId {
    /// The core: catalog and markers.
    pub(crate) const CATALOG: EngineId = EngineId(0);
    /// The auth engine.
    pub(crate) const AUTH: EngineId = EngineId(1);
    /// The content engine.
    pub(crate) const CONTENT: EngineId = EngineId(2);
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

    /// Install a committed section at `seq`. Deterministic and idempotent:
    /// a section at or below the engine's durable mark is skipped.
    fn apply(&self, seq: Seq, collection: u32, format: u16, body: &[u8]) -> Result<()>;

    /// The highest sequence number this engine's own files hold. Recovery
    /// replays the log from just above the lowest mark of all engines.
    fn durable_through(&self) -> Seq;

    /// Write the engine's own files up to everything applied so far and
    /// return the new durable mark.
    fn checkpoint(&self) -> Result<Seq>;
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

    /// Snapshot-isolation check: fail when a key this work writes was
    /// committed after `snapshot`.
    fn validate(&self, snapshot: Seq) -> std::result::Result<(), Conflict>;

    /// Record that the staged keys are written at `seq`.
    fn reserve(&self, seq: Seq);

    /// Append the section body for the log.
    fn encode(&self, seq: Seq, out: &mut Vec<u8>) -> Result<()>;
}
