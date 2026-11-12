//! Verifiable audit exports (feature `audit-export`).
//!
//! A realm's audit chain links its records with a keyed BLAKE3 hash: only
//! someone with the key can check it, and anyone with the key could forge
//! it. An export lets an auditor check records without either: the
//! database verifies its chain from the first record, takes the records in
//! the asked range, and signs them with an Ed25519 key derived from the
//! root key. The auditor checks the signature with the realm's public key
//! ([`Auth::audit_public_key`](crate::Auth::audit_public_key), published
//! out of band).
//!
//! What a valid export proves: the database's chain verified up to its
//! last record when the export was made, and these are its records with
//! consecutive ids from `first` up to `end`, unchanged, none left out. Each
//! export also carries the chain's link before its first record and after
//! its last, so exports of consecutive ranges join: an auditor who holds
//! both checks that neither was cut or shortened
//! ([`AuditExport::continues`]).
//!
//! The signed bytes:
//!
//! ```text
//! magic "NXDBAUDT" | version u16 | realm u32 | chain length u64 |
//! first u64 | end u64 | link before [32] | link after [32] |
//! count u32 | count x (id u64 | time ns u64 | commit u64 | n u32 |
//!                      action str32 | target str32)
//! ```
//!
//! followed by the 64-byte signature.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crypt_io::sign::{Ed25519PublicKey, Ed25519SigningKey};

use crate::{
    core::codec::{Reader, Writer},
    error::{Error, Result},
};

const MAGIC: &[u8; 8] = b"NXDBAUDT";
const VERSION: u16 = 1;
const SIGNATURE: usize = 64;
const WHAT: &str = "an audit export";

/// One event of an audit export: what happened, when, and in which
/// commit. Events name ids and kinds only, never an identifier, a token, or
/// a hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    id: u64,
    nanos: u64,
    commit: u64,
    n: u32,
    action: String,
    target: String,
}

impl AuditEvent {
    /// The record's id in the realm's chain: consecutive from 0.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// When it happened.
    #[must_use]
    pub fn at(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_nanos(self.nanos)
    }

    /// The commit's position (as [`Position::get`](crate::Position::get)
    /// gives it) and the event's place among that commit's events.
    #[must_use]
    pub const fn commit(&self) -> (u64, u32) {
        (self.commit, self.n)
    }

    /// What happened: `account.created`, `session.issued`,
    /// `session.revoked`, `standing.changed`, and so on.
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }

    /// What it happened to: `account <id>`, `session`, and so on.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }
}

/// A signed range of a realm's audit chain, made by
/// [`Auth::audit_export`](crate::Auth::audit_export): its events and a
/// signature that the database verified the chain and none of the range is
/// changed or left out. See [`from_bytes`](Self::from_bytes) to check one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditExport {
    collection: u32,
    chain_len: u64,
    first: u64,
    end: u64,
    before: [u8; 32],
    after: [u8; 32],
    events: Vec<AuditEvent>,
    signature: [u8; SIGNATURE],
}

impl AuditExport {
    /// The events, in chain order.
    #[must_use]
    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    /// The ids exported: from `first` up to, not including, `end`.
    #[must_use]
    pub const fn range(&self) -> std::ops::Range<u64> {
        self.first..self.end
    }

    /// How many records the chain held when the export was made.
    #[must_use]
    pub const fn chain_len(&self) -> u64 {
        self.chain_len
    }

    /// True when this export starts right after `earlier` ends, in the same
    /// chain: together they cover both ranges with nothing left out.
    #[must_use]
    pub fn continues(&self, earlier: &AuditExport) -> bool {
        self.collection == earlier.collection
            && earlier.end == self.first
            && self.before == earlier.after
    }

    /// The export as bytes: the signed content and the signature.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.signed_bytes();
        out.extend_from_slice(&self.signature);
        out
    }

    /// Check `bytes` against the realm's public key and return the export.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the signature does not verify under
    /// `public_key` or the bytes are not an export.
    pub fn from_bytes(bytes: &[u8], public_key: &[u8; 32]) -> Result<AuditExport> {
        let invalid = || Error::invalid("audit export", "the signature does not verify");
        let split = bytes.len().checked_sub(SIGNATURE).ok_or_else(invalid)?;
        let (signed, signature) = bytes.split_at(split);
        let key = Ed25519PublicKey::from_bytes(public_key).map_err(|_| invalid())?;
        key.check(signed, signature).map_err(|_| invalid())?;
        let mut export = decode(signed).map_err(|_| invalid())?;
        export.signature.copy_from_slice(signature);
        Ok(export)
    }

    fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.events.len() * 64);
        let mut w = Writer::new(&mut out);
        w.bytes(MAGIC);
        w.u16(VERSION);
        w.u32(self.collection);
        w.u64(self.chain_len);
        w.u64(self.first);
        w.u64(self.end);
        w.bytes(&self.before);
        w.bytes(&self.after);
        w.u32(self.events.len() as u32);
        for event in &self.events {
            w.u64(event.id);
            w.u64(event.nanos);
            w.u64(event.commit);
            w.u32(event.n);
            put_str(&mut w, &event.action);
            put_str(&mut w, &event.target);
        }
        out
    }
}

fn put_str(w: &mut Writer<'_>, s: &str) {
    w.u32(s.len() as u32);
    w.bytes(s.as_bytes());
}

fn get_str(r: &mut Reader<'_>) -> Result<String> {
    let len = r.u32()? as usize;
    let bytes = r.take(len)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::corrupt(WHAT, 0))
}

fn decode(signed: &[u8]) -> Result<AuditExport> {
    let mut r = Reader::new(signed, WHAT, 0);
    if r.fixed::<8>()? != *MAGIC || r.u16()? != VERSION {
        return Err(Error::corrupt(WHAT, 0));
    }
    let collection = r.u32()?;
    let chain_len = r.u64()?;
    let first = r.u64()?;
    let end = r.u64()?;
    let before = r.fixed()?;
    let after = r.fixed()?;
    let count = r.u32()?;
    // Each event takes at least 36 bytes: no count beyond what the bytes hold.
    let mut events = Vec::with_capacity((count as usize).min(signed.len() / 36));
    for _ in 0..count {
        events.push(AuditEvent {
            id: r.u64()?,
            nanos: r.u64()?,
            commit: r.u64()?,
            n: r.u32()?,
            action: get_str(&mut r)?,
            target: get_str(&mut r)?,
        });
    }
    r.finish()?;
    Ok(AuditExport {
        collection,
        chain_len,
        first,
        end,
        before,
        after,
        events,
        signature: [0; SIGNATURE],
    })
}

/// One verified chain record, as the export takes it.
pub(crate) struct Verified {
    pub(crate) id: u64,
    pub(crate) nanos: u64,
    pub(crate) actor: String,
    pub(crate) action: String,
    pub(crate) target: String,
    pub(crate) prev_hash: [u8; 32],
    pub(crate) hash: [u8; 32],
}

/// The commit and event number in an actor `commit <seq>.<n>`.
fn commit_of(actor: &str) -> Result<(u64, u32)> {
    let rest = actor
        .strip_prefix("commit ")
        .ok_or(Error::corrupt("an audit record (actor)", 0))?;
    let (seq, n) = rest
        .split_once('.')
        .ok_or(Error::corrupt("an audit record (actor)", 0))?;
    Ok((
        seq.parse()
            .map_err(|_| Error::corrupt("an audit record (actor)", 0))?,
        n.parse()
            .map_err(|_| Error::corrupt("an audit record (actor)", 0))?,
    ))
}

/// Sign the records with ids in `first..end` out of `chain`, every record
/// of the chain in order and verified (`end` at most the chain's length).
pub(crate) fn export(
    collection: u32,
    chain: &[Verified],
    first: u64,
    end: u64,
    seed: &[u8; 32],
) -> Result<AuditExport> {
    let link = |id: u64| -> [u8; 32] {
        // The link before record `id` is its prev hash; past the end, the
        // last record's hash; an empty chain links to zeros.
        match usize::try_from(id).ok().and_then(|i| chain.get(i)) {
            Some(record) => record.prev_hash,
            None => chain.last().map_or([0; 32], |r| r.hash),
        }
    };
    let mut events = Vec::new();
    for record in chain.iter().filter(|r| r.id >= first && r.id < end) {
        let (commit, n) = commit_of(&record.actor)?;
        events.push(AuditEvent {
            id: record.id,
            nanos: record.nanos,
            commit,
            n,
            action: record.action.clone(),
            target: record.target.clone(),
        });
    }
    let mut export = AuditExport {
        collection,
        chain_len: chain.len() as u64,
        first,
        end,
        before: link(first),
        after: link(end),
        events,
        signature: [0; SIGNATURE],
    };
    let key = Ed25519SigningKey::from_seed(seed)
        .map_err(|e| Error::storage("deriving the audit signing key", e))?;
    export.signature = key.sign(&export.signed_bytes());
    Ok(export)
}

/// The realm's public key for exports signed with `seed`.
pub(crate) fn public_key(seed: &[u8; 32]) -> Result<[u8; 32]> {
    Ed25519SigningKey::from_seed(seed)
        .map(|key| key.public_key())
        .map_err(|e| Error::storage("deriving the audit signing key", e))
}

/// The export decoder, for fuzzing and tests.
#[cfg(any(fuzzing, test))]
pub(crate) fn fuzz(data: &[u8]) {
    let _ = decode(data);
    let _ = AuditExport::from_bytes(data, &[9; 32]);
}
