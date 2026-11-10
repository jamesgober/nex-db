//! The session table: sessions and revocation tombstones by token digest.
//!
//! Entries live in the fixed-key [`Table`]: a validation reads one slot
//! without a lock and allocates nothing (the payload's first 56 bytes are
//! inline, the rest in an extension block). Each slot keeps its last use in
//! the word readers may raise, saved by checkpoints. The timer wheel
//! reclaims a slot when its time passes: a session at its expiry (or idle
//! limit), a tombstone when its session would have expired.
//!
//! The table is read-latest by design: a revocation is visible to every
//! reader at once, so no snapshot can revive a revoked session. Signing an
//! account out everywhere turns each of its live sessions into a tombstone
//! when the commit applies (found through a per-account index), so a
//! validation needs no epoch lookup. It lives in memory; a checkpoint saves
//! it and the log after the checkpoint rebuilds the rest at open.

use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard, PoisonError, RwLock},
};

use super::types::{MAX_PAYLOAD, Payload, RevokeReason, Session};
use crate::{
    ids::AccountId,
    table::{At, Refused, Table},
    wheel::Wheel,
};

/// Words per slot: account (2), created, expires, idle, recheck, a meta
/// word (kind, reason, payload length, epoch), and the payload's start.
const WORDS: usize = 14;
/// Payload bytes kept in the slot itself.
const INLINE: usize = (WORDS - 7) * 8;
/// Words of an extension block: the rest of a full payload.
const EXT: usize = (MAX_PAYLOAD - INLINE) / 8;
const _: () = assert!(INLINE + EXT * 8 == MAX_PAYLOAD);

const KIND_LIVE: u64 = 1;
const KIND_REVOKED: u64 = 2;
const KIND_DECOY: u64 = 3;

/// How long a tombstone of a session whose expiry is unknown is kept.
const TOMBSTONE_MS: u64 = 24 * 60 * 60 * 1000;
/// Shards of the table, and the slots in the first index of each.
const SHARDS: usize = 16;
const BASE_SLOTS: usize = 512;
/// The wheel's tick: a slot is reclaimed at most this long after its time.
const TICK_MS: u64 = 1000;

type Words = [u64; WORDS];
type ExtWords = [u64; EXT];

/// One entry as a reader sees it: a live session, or the tombstone a
/// revocation leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// The session is returned by value, payload inline, so a read allocates
// nothing; boxing it would allocate on every validation.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Slot {
    Live(Session),
    Revoked(RevokeReason),
    /// A token planted for attackers to find: never a session.
    Decoy,
}

/// Where an entry was found, for [`SessionTable::touch`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct Place(At);

/// The table has no room for another entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Full;

/// Why a session older than its account's `epoch` ended.
fn ended_by(epoch: u32) -> RevokeReason {
    if epoch == super::ERASED_EPOCH {
        RevokeReason::Erased
    } else {
        RevokeReason::SignedOutEverywhere
    }
}

fn reason_code(reason: RevokeReason) -> u64 {
    match reason {
        RevokeReason::Revoked => 1,
        RevokeReason::Rotated => 2,
        RevokeReason::SignedOutEverywhere => 3,
        RevokeReason::Erased => 4,
    }
}

fn reason_of(code: u64) -> Option<RevokeReason> {
    Some(match code {
        1 => RevokeReason::Revoked,
        2 => RevokeReason::Rotated,
        3 => RevokeReason::SignedOutEverywhere,
        4 => RevokeReason::Erased,
        _ => return None,
    })
}

fn word(bytes: &[u8]) -> u64 {
    let mut w = [0; 8];
    w.copy_from_slice(bytes);
    u64::from_le_bytes(w)
}

fn account_of(words: &Words) -> AccountId {
    let mut b = [0; 16];
    b[..8].copy_from_slice(&words[0].to_le_bytes());
    b[8..].copy_from_slice(&words[1].to_le_bytes());
    AccountId::from_bytes(b)
}

fn kind(words: &Words) -> u64 {
    words[6] & 0xFF
}

fn encode_live(session: &Session) -> (Words, Option<ExtWords>) {
    let payload = session.payload.as_bytes();
    let account = session.account.as_bytes();
    let mut words = [0; WORDS];
    words[0] = word(&account[..8]);
    words[1] = word(&account[8..]);
    words[2] = session.created_ms;
    words[3] = session.expires_ms;
    words[4] = session.idle_ms;
    words[5] = session.recheck_ms;
    words[6] = KIND_LIVE | ((payload.len() as u64) << 16) | (u64::from(session.epoch) << 32);
    let mut bytes = [0; MAX_PAYLOAD];
    bytes[..payload.len()].copy_from_slice(payload);
    for (w, chunk) in words[7..].iter_mut().zip(bytes[..INLINE].chunks_exact(8)) {
        *w = word(chunk);
    }
    let ext = (payload.len() > INLINE).then(|| {
        let mut ext = [0; EXT];
        for (w, chunk) in ext.iter_mut().zip(bytes[INLINE..].chunks_exact(8)) {
            *w = word(chunk);
        }
        ext
    });
    (words, ext)
}

fn encode_revoked(account: AccountId, reason: RevokeReason, until_ms: u64) -> Words {
    let account = account.as_bytes();
    let mut words = [0; WORDS];
    words[0] = word(&account[..8]);
    words[1] = word(&account[8..]);
    words[3] = until_ms;
    words[6] = KIND_REVOKED | (reason_code(reason) << 8);
    words
}

/// The idle limit that marks a single-use token in the session table: never
/// listed or counted as a session.
pub(crate) const SINGLE_USE_IDLE: u64 = u64::MAX;

fn decode(words: &Words, ext: Option<&ExtWords>) -> Option<Slot> {
    match kind(words) {
        KIND_LIVE => {
            let len = usize::from((words[6] >> 16) as u16);
            let mut bytes = [0; MAX_PAYLOAD];
            for (chunk, w) in bytes[..INLINE].chunks_exact_mut(8).zip(&words[7..]) {
                chunk.copy_from_slice(&w.to_le_bytes());
            }
            if let Some(ext) = ext {
                for (chunk, w) in bytes[INLINE..].chunks_exact_mut(8).zip(ext) {
                    chunk.copy_from_slice(&w.to_le_bytes());
                }
            }
            Some(Slot::Live(Session {
                account: account_of(words),
                created_ms: words[2],
                expires_ms: words[3],
                epoch: (words[6] >> 32) as u32,
                idle_ms: words[4],
                recheck_ms: words[5],
                payload: Payload::from_array(len, bytes)?,
            }))
        }
        KIND_REVOKED => reason_of((words[6] >> 8) & 0xFF).map(Slot::Revoked),
        KIND_DECOY => Some(Slot::Decoy),
        _ => None,
    }
}

/// When the entry's slot can be reclaimed: a session at its expiry or idle
/// limit, whichever is first; a tombstone at its own time.
fn deadline(words: &Words, seen: u64) -> u64 {
    match (kind(words), words[4]) {
        (KIND_LIVE, 0) => words[3],
        (KIND_LIVE, idle) => words[3].min(seen.saturating_add(idle)),
        _ => words[3],
    }
}

/// What one writer at a time changes.
#[derive(Debug)]
struct Writer {
    wheel: Wheel<u64>,
    /// Where each account's live sessions are.
    accounts: HashMap<AccountId, Vec<u64>>,
}

impl Writer {
    fn index(&mut self, account: AccountId, at: At) {
        self.accounts.entry(account).or_default().push(at.to_u64());
    }

    fn unindex(&mut self, account: AccountId, at: At) {
        if let Some(places) = self.accounts.get_mut(&account) {
            places.retain(|p| *p != at.to_u64());
            if places.is_empty() {
                let _ = self.accounts.remove(&account);
            }
        }
    }
}

/// Sessions by token digest.
#[derive(Debug)]
pub(crate) struct SessionTable {
    table: Table<WORDS, EXT>,
    writer: Mutex<Writer>,
}

impl SessionTable {
    /// A table with room for `max` entries, its clock at `now_ms`.
    pub(crate) fn new(max: usize, now_ms: u64) -> Self {
        SessionTable {
            table: Table::new(SHARDS, BASE_SLOTS, max),
            writer: Mutex::new(Writer {
                wheel: Wheel::new(TICK_MS, now_ms),
                accounts: HashMap::new(),
            }),
        }
    }

    fn writer(&self) -> MutexGuard<'_, Writer> {
        self.writer.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The slot for `digest`, when a live session was last used, and where
    /// it is. Takes no lock and allocates nothing.
    pub(crate) fn get_seen(&self, digest: &[u8; 32]) -> Option<(Slot, u64, Place)> {
        let found = self.table.get(digest)?;
        let slot = decode(&found.words, found.ext.as_ref())?;
        Some((slot, found.aux, Place(found.at)))
    }

    /// The slot for `digest`. Takes no lock and allocates nothing.
    pub(crate) fn get(&self, digest: &[u8; 32]) -> Option<Slot> {
        self.get_seen(digest).map(|(slot, ..)| slot)
    }

    /// Record that the session found at `place` was used at `now_ms`: one
    /// relaxed atomic. Should the session have been reclaimed and its slot
    /// reused since, the new session's last use becomes `now_ms`, which is
    /// no earlier than its creation: harmless.
    pub(crate) fn touch(&self, place: Place, now_ms: u64) {
        self.table.raise_aux(place.0, now_ms);
    }

    /// Install a live session. A digest already in the table keeps its
    /// entry, so a revoked one stays revoked. A session issued before its
    /// account's current epoch (`epoch`) goes in as a tombstone.
    pub(crate) fn insert(
        &self,
        digest: [u8; 32],
        session: Session,
        epoch: u32,
    ) -> Result<(), Full> {
        self.put(digest, session, session.created_ms, epoch)
    }

    fn put(&self, digest: [u8; 32], session: Session, seen: u64, epoch: u32) -> Result<(), Full> {
        let mut w = self.writer();
        let live = session.epoch >= epoch;
        let (words, ext) = if live {
            encode_live(&session)
        } else {
            let reason = ended_by(epoch);
            (
                encode_revoked(session.account, reason, session.expires_ms),
                None,
            )
        };
        match self.table.insert(&digest, &words, ext.as_ref(), seen) {
            Ok(at) => {
                let _ = w.wheel.insert(deadline(&words, seen), at.to_u64());
                if live {
                    w.index(session.account, at);
                }
                Ok(())
            }
            Err(Refused::Exists(_)) => Ok(()),
            Err(Refused::Full) => Err(Full),
        }
    }

    fn put_tombstone(
        &self,
        w: &mut Writer,
        digest: [u8; 32],
        reason: RevokeReason,
        until_ms: u64,
    ) -> Result<(), Full> {
        let words = encode_revoked(AccountId::from_bytes([0; 16]), reason, until_ms);
        match self.table.insert(&digest, &words, None, 0) {
            Ok(at) => {
                let _ = w.wheel.insert(until_ms, at.to_u64());
                Ok(())
            }
            Err(Refused::Exists(_)) => Ok(()),
            Err(Refused::Full) => Err(Full),
        }
    }

    /// Hold `digest` as a decoy: never a session, never reclaimed. A digest
    /// already in the table keeps its entry.
    pub(crate) fn plant_decoy(&self, digest: [u8; 32]) -> Result<(), Full> {
        let _w = self.writer();
        let mut words = [0; WORDS];
        words[3] = u64::MAX;
        words[6] = KIND_DECOY;
        match self.table.insert(&digest, &words, None, 0) {
            Ok(_) | Err(Refused::Exists(_)) => Ok(()),
            Err(Refused::Full) => Err(Full),
        }
    }

    /// Replace the session with a tombstone, kept until the session would
    /// have expired (or a day, when it is not known). `now_ms` is the
    /// revocation's own time, so a replay keeps the same tombstone.
    pub(crate) fn revoke(
        &self,
        digest: [u8; 32],
        reason: RevokeReason,
        now_ms: u64,
    ) -> Result<(), Full> {
        let mut w = self.writer();
        match self.table.get(&digest) {
            Some(found) => {
                let account = account_of(&found.words);
                if kind(&found.words) == KIND_LIVE {
                    w.unindex(account, found.at);
                }
                // The wheel's timer for the slot is no later than the
                // session's expiry; it is set again when it fires.
                let words = encode_revoked(account, reason, found.words[3]);
                let _ = self.table.update(found.at, &words, None);
                Ok(())
            }
            None => self.put_tombstone(&mut w, digest, reason, now_ms.saturating_add(TOMBSTONE_MS)),
        }
    }

    /// The account was signed out everywhere at `epoch`: every live session
    /// it has from an earlier epoch becomes a tombstone.
    pub(crate) fn raise(&self, account: AccountId, epoch: u32) {
        let mut w = self.writer();
        let Some(places) = w.accounts.remove(&account) else {
            return;
        };
        let mut kept = Vec::new();
        for place in places {
            let at = At::from_u64(place);
            let Some((_, found)) = self.table.read_at(at) else {
                continue;
            };
            match decode(&found.words, found.ext.as_ref()) {
                Some(Slot::Live(session)) if session.epoch < epoch => {
                    let words = encode_revoked(account, ended_by(epoch), session.expires_ms);
                    let _ = self.table.update(at, &words, None);
                }
                Some(Slot::Live(_)) => kept.push(place),
                _ => {}
            }
        }
        if !kept.is_empty() {
            let _ = w.accounts.insert(account, kept);
        }
    }

    /// Reclaim the slots whose time has passed at `now_ms`: an expired
    /// session is invalid either way, and a tombstone outlives its session
    /// only to say why it ended. Returns how many were reclaimed. Visits
    /// only the wheel's due slots, so a call with nothing due is cheap.
    pub(crate) fn reclaim(&self, now_ms: u64) -> usize {
        let mut w = self.writer();
        let mut due = Vec::new();
        w.wheel.advance(now_ms, |place| due.push(place));
        let mut reclaimed = 0;
        for place in due {
            let at = At::from_u64(place);
            let Some((_, found)) = self.table.read_at(at) else {
                continue;
            };
            let when = deadline(&found.words, found.aux);
            if when <= now_ms {
                if kind(&found.words) == KIND_LIVE {
                    w.unindex(account_of(&found.words), at);
                }
                if self.table.remove(at) {
                    reclaimed += 1;
                }
            } else {
                // Used since the timer was set, or a tombstone now: later.
                let _ = w.wheel.insert(when, place);
            }
        }
        reclaimed
    }

    /// Live sessions of `account` that are still valid at `now_ms` under
    /// `epoch`, from the per-account index.
    pub(crate) fn live_for(&self, account: AccountId, epoch: u32, now_ms: u64) -> u32 {
        u32::try_from(self.sessions_of(account, epoch, now_ms).len()).unwrap_or(u32::MAX)
    }

    /// The live sessions of `account` at `epoch` (not single-use tokens):
    /// each with its digest and when it was last used.
    pub(crate) fn sessions_of(
        &self,
        account: AccountId,
        epoch: u32,
        now_ms: u64,
    ) -> Vec<([u8; 32], Session, u64)> {
        let w = self.writer();
        let Some(places) = w.accounts.get(&account) else {
            return Vec::new();
        };
        places
            .iter()
            .filter_map(|place| {
                let (digest, found) = self.table.read_at(At::from_u64(*place))?;
                if deadline(&found.words, found.aux) <= now_ms {
                    return None;
                }
                match decode(&found.words, found.ext.as_ref())? {
                    Slot::Live(s)
                        if s.account == account
                            && s.epoch == epoch
                            && now_ms < s.expires_ms
                            && s.idle_ms != SINGLE_USE_IDLE =>
                    {
                        Some((digest, s, found.aux))
                    }
                    _ => None,
                }
            })
            .collect()
    }

    /// Number of entries, tombstones included.
    pub(crate) fn len(&self) -> usize {
        self.table.len()
    }

    /// Every entry, for a checkpoint: the digest, the slot, and a time (when
    /// a live session was last used; until when a tombstone is kept).
    pub(crate) fn snapshot(&self) -> Vec<([u8; 32], Slot, u64)> {
        let _w = self.writer();
        let mut out = Vec::with_capacity(self.table.len());
        self.table.for_each(|digest, found| {
            if let Some(slot) = decode(&found.words, found.ext.as_ref()) {
                let time = match slot {
                    Slot::Live(_) => found.aux,
                    Slot::Revoked(_) => found.words[3],
                    Slot::Decoy => 0,
                };
                out.push((digest, slot, time));
            }
        });
        out
    }

    /// Put an entry back as a checkpoint held it, with its time (see
    /// [`snapshot`](Self::snapshot)); `epoch` is the account's current one.
    pub(crate) fn restore(
        &self,
        digest: [u8; 32],
        slot: Slot,
        time: u64,
        epoch: u32,
    ) -> Result<(), Full> {
        match slot {
            Slot::Live(session) => self.put(digest, session, time, epoch),
            Slot::Revoked(reason) => {
                let mut w = self.writer();
                self.put_tombstone(&mut w, digest, reason, time)
            }
            Slot::Decoy => self.plant_decoy(digest),
        }
    }
}

/// The current epoch of each account that was ever signed out everywhere.
/// An account not listed is at epoch 0. Read by staging and when a commit
/// applies, never by a validation.
#[derive(Debug, Default)]
pub(crate) struct EpochTable {
    epochs: RwLock<HashMap<AccountId, u32>>,
}

impl EpochTable {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The account's epoch. Allocates nothing.
    pub(crate) fn get(&self, account: AccountId) -> u32 {
        let epochs = self.epochs.read().unwrap_or_else(PoisonError::into_inner);
        epochs.get(&account).copied().unwrap_or(0)
    }

    /// Raise the account's epoch to `epoch`. An epoch never goes down, so a
    /// replayed or reordered raise is harmless.
    pub(crate) fn raise(&self, account: AccountId, epoch: u32) {
        let mut epochs = self.epochs.write().unwrap_or_else(PoisonError::into_inner);
        let current = epochs.entry(account).or_insert(0);
        *current = (*current).max(epoch);
    }

    /// Every account's epoch, for a checkpoint.
    pub(crate) fn snapshot(&self) -> Vec<(AccountId, u32)> {
        let epochs = self.epochs.read().unwrap_or_else(PoisonError::into_inner);
        epochs.iter().map(|(a, e)| (*a, *e)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        Session {
            account: AccountId::from_bytes([7; 16]),
            created_ms: 1,
            expires_ms: 10_000,
            epoch: 0,
            idle_ms: 0,
            recheck_ms: 0,
            payload: Payload::EMPTY,
        }
    }

    fn table() -> SessionTable {
        SessionTable::new(10_000, 0)
    }

    /// A digest spread like a MAC output.
    fn digest(n: u8) -> [u8; 32] {
        let mut d = [n; 32];
        d[..8].copy_from_slice(
            &u64::from(n)
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .to_le_bytes(),
        );
        d
    }

    #[test]
    fn test_reclaim_drops_expired_sessions_and_old_tombstones() {
        let table = table();
        table.insert(digest(1), session(), 0).unwrap(); // expires at 10 s
        let longer = Session {
            expires_ms: 100_000,
            ..session()
        };
        table.insert(digest(2), longer, 0).unwrap();
        table.revoke(digest(2), RevokeReason::Revoked, 5).unwrap(); // kept until 100 s
        table.revoke(digest(3), RevokeReason::Revoked, 5).unwrap(); // unknown: a day
        assert_eq!(table.reclaim(50_000), 1);
        assert_eq!(table.get(&digest(1)), None);
        assert_eq!(
            table.get(&digest(2)),
            Some(Slot::Revoked(RevokeReason::Revoked))
        );
        assert_eq!(table.reclaim(100_000), 1);
        assert_eq!(table.len(), 1);
        // The wheel rounds up to its next tick.
        assert_eq!(table.reclaim(5 + TOMBSTONE_MS), 0);
        assert_eq!(table.reclaim(5 + TOMBSTONE_MS + TICK_MS), 1);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_idle_session_is_reclaimed_only_after_its_idle_limit() {
        let table = table();
        let idle = Session {
            idle_ms: 3_000,
            ..session()
        };
        table.insert(digest(1), idle, 0).unwrap();
        let (_, _, place) = table.get_seen(&digest(1)).unwrap();
        table.touch(place, 2_500);
        // Due 3 s after creation, but used at 2.5 s: kept until 5.5 s.
        assert_eq!(table.reclaim(4_000), 0);
        assert_eq!(table.reclaim(5_499), 0);
        assert_eq!(table.reclaim(6_000), 1);
    }

    #[test]
    fn test_payload_and_last_use_round_trip() {
        for len in [0, 11, INLINE, INLINE + 1, MAX_PAYLOAD] {
            let table = table();
            let bytes: Vec<u8> = (0..len).map(|i| i as u8 ^ 0x5A).collect();
            let with = Session {
                payload: Payload::new(&bytes).unwrap(),
                ..session()
            };
            table.insert(digest(5), with, 0).unwrap();
            assert_eq!(table.get(&digest(5)), Some(Slot::Live(with)));
            let (_, _, place) = table.get_seen(&digest(5)).unwrap();
            table.touch(place, 7);
            table.touch(place, 4);
            assert_eq!(table.get_seen(&digest(5)).map(|(_, seen, _)| seen), Some(7));
            let other = SessionTable::new(10_000, 0);
            for (digest, slot, seen) in table.snapshot() {
                other.restore(digest, slot, seen, 0).unwrap();
            }
            assert_eq!(
                other.get_seen(&digest(5)).map(|(s, seen, _)| (s, seen)),
                Some((Slot::Live(with), 7))
            );
        }
    }

    #[test]
    fn test_live_for_counts_only_current_unexpired_sessions() {
        let table = table();
        table.insert(digest(1), session(), 0).unwrap();
        let later = Session {
            epoch: 1,
            ..session()
        };
        table.insert(digest(2), later, 0).unwrap();
        table.insert(digest(3), session(), 0).unwrap();
        table.revoke(digest(3), RevokeReason::Revoked, 0).unwrap();
        let other = Session {
            account: AccountId::from_bytes([8; 16]),
            ..session()
        };
        table.insert(digest(4), other, 0).unwrap();
        let account = AccountId::from_bytes([7; 16]);
        assert_eq!(table.live_for(account, 0, 5), 1);
        assert_eq!(table.live_for(account, 1, 5), 1);
        assert_eq!(table.live_for(account, 0, 10_000), 0);
    }

    #[test]
    fn test_raise_turns_older_sessions_into_tombstones() {
        let table = table();
        let account = AccountId::from_bytes([7; 16]);
        table.insert(digest(1), session(), 0).unwrap();
        table.insert(digest(2), session(), 0).unwrap();
        table.raise(account, 1);
        let out = Some(Slot::Revoked(RevokeReason::SignedOutEverywhere));
        assert_eq!(table.get(&digest(1)), out);
        assert_eq!(table.get(&digest(2)), out);
        // Issued before the raise, applied after it.
        table.insert(digest(3), session(), 1).unwrap();
        assert_eq!(table.get(&digest(3)), out);
        let current = Session {
            epoch: 1,
            ..session()
        };
        table.insert(digest(4), current, 1).unwrap();
        assert!(matches!(table.get(&digest(4)), Some(Slot::Live(_))));
        assert_eq!(table.live_for(account, 1, 5), 1);
    }

    #[test]
    fn test_epoch_only_rises() {
        let epochs = EpochTable::new();
        let account = AccountId::from_bytes([7; 16]);
        assert_eq!(epochs.get(account), 0);
        epochs.raise(account, 2);
        epochs.raise(account, 1);
        assert_eq!(epochs.get(account), 2);
    }

    #[test]
    fn test_insert_then_get_returns_live() {
        let table = table();
        table.insert(digest(1), session(), 0).unwrap();
        assert_eq!(table.get(&digest(1)), Some(Slot::Live(session())));
        assert_eq!(table.get(&digest(2)), None);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_revoke_then_insert_stays_revoked() {
        let table = table();
        table.insert(digest(1), session(), 0).unwrap();
        table.revoke(digest(1), RevokeReason::Revoked, 0).unwrap();
        table.insert(digest(1), session(), 0).unwrap();
        assert_eq!(
            table.get(&digest(1)),
            Some(Slot::Revoked(RevokeReason::Revoked))
        );
    }
}
