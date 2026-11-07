//! A table from 32-byte keys to fixed-size values, read without locks.
//!
//! Self-contained: it uses nothing else in the crate, so it can move to a
//! crate of its own (`dev/PLAN.md` D-055).
//!
//! - **Shards**, chosen by the key's top bits. One writer at a time per
//!   shard (a mutex only writers take); readers take no lock and write
//!   nothing.
//! - **Levels**: each shard holds open-addressed arrays, allocated as it
//!   fills, each twice the size of the one before. An entry stays in the
//!   level it was put in, so nothing moves under a reader. A level whose
//!   entries are all gone is cleared for reuse.
//! - **Control bytes**, eight to a `u64`, are matched eight at a time.
//! - **Slots** are runs of atomic words read as a sequence lock: a reader
//!   copies the words and retries if a writer changed the slot's sequence
//!   meanwhile. Each slot also has one word outside the lock (`aux`) that
//!   readers may raise without a writer, such as a last-used time.
//! - **Extensions**: a value longer than the inline words keeps the rest in
//!   a block from a per-shard pool, read under the owning slot's sequence.
//!
//! Keys must be uniformly distributed (they are MAC outputs): the table
//! uses their bytes as the hash.

// Not every caller uses every call (the benchmarks include this module on
// its own).
#![allow(dead_code)]

#[cfg(test)]
mod tests;

use std::sync::{OnceLock, PoisonError};

#[cfg(all(nex_loom, test))]
use loom::sync::{
    Mutex,
    atomic::{AtomicU64, AtomicUsize, Ordering, fence},
};
#[cfg(not(all(nex_loom, test)))]
use std::sync::{
    Mutex,
    atomic::{AtomicU64, AtomicUsize, Ordering, fence},
};

/// The control byte of a slot never used since the level was cleared.
const EMPTY: u8 = 0xFF;
/// The control byte of a slot whose entry was removed.
const DELETED: u8 = 0x80;
const LO: u64 = 0x0101_0101_0101_0101;
const HI: u64 = 0x8080_8080_8080_8080;
/// Extension blocks are allocated this many at a time.
#[cfg(not(all(nex_loom, test)))]
const EXT_CHUNK: usize = 1024;
#[cfg(all(nex_loom, test))]
const EXT_CHUNK: usize = 2;
/// A level is filled to at most this many eighths before the next is used.
const FILL_EIGHTHS: usize = 7;
/// The most entries a table is sized for, which bounds what it sets aside
/// for levels and extension blocks it has not allocated yet.
pub(crate) const MAX_ENTRIES: usize = u32::MAX as usize;

fn spin() {
    #[cfg(all(nex_loom, test))]
    loom::thread::yield_now();
    #[cfg(not(all(nex_loom, test)))]
    std::hint::spin_loop();
}

/// Where an entry is: shard, level, slot. Stable while the entry exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct At {
    shard: u16,
    level: u8,
    index: u32,
}

impl At {
    /// As one `u64`, for keeping in other structures.
    pub(crate) fn to_u64(self) -> u64 {
        (u64::from(self.shard) << 40) | (u64::from(self.level) << 32) | u64::from(self.index)
    }

    pub(crate) fn from_u64(v: u64) -> At {
        At {
            shard: (v >> 40) as u16,
            level: (v >> 32) as u8,
            index: v as u32,
        }
    }
}

/// An entry as read: its place, its words, its extension, and `aux`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Found<const W: usize, const X: usize> {
    pub(crate) at: At,
    pub(crate) words: [u64; W],
    pub(crate) ext: Option<[u64; X]>,
    pub(crate) aux: u64,
}

/// Why an insert did not happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    /// The key is already in the table, here.
    Exists(At),
    /// The shard has no room left.
    Full,
}

struct Cell<const W: usize> {
    seq: AtomicU64,
    key: [AtomicU64; 4],
    words: [AtomicU64; W],
    /// Extension block index plus one; 0 for none.
    ext: AtomicU64,
    aux: AtomicU64,
}

impl<const W: usize> Cell<W> {
    fn new() -> Self {
        Cell {
            seq: AtomicU64::new(0),
            key: std::array::from_fn(|_| AtomicU64::new(0)),
            words: std::array::from_fn(|_| AtomicU64::new(0)),
            ext: AtomicU64::new(0),
            aux: AtomicU64::new(0),
        }
    }
}

struct Ext<const X: usize> {
    words: [AtomicU64; X],
}

struct Level<const W: usize> {
    ctrl: Box<[AtomicU64]>,
    cells: Box<[Cell<W>]>,
    /// Groups minus one (groups are a power of two).
    mask: usize,
    live: AtomicUsize,
}

impl<const W: usize> Level<W> {
    fn new(groups: usize) -> Self {
        Level {
            ctrl: (0..groups).map(|_| AtomicU64::new(u64::MAX)).collect(),
            cells: (0..groups * 8).map(|_| Cell::new()).collect(),
            mask: groups - 1,
            live: AtomicUsize::new(0),
        }
    }

    fn capacity(&self) -> usize {
        self.cells.len()
    }
}

/// Bytes of `group` equal to `byte`, as their top bits. May include a
/// false match next to a true one; callers compare keys.
fn match_byte(group: u64, byte: u8) -> u64 {
    let cmp = group ^ (LO * u64::from(byte));
    cmp.wrapping_sub(LO) & !cmp & HI
}

/// Bytes of `group` that are `EMPTY`.
fn match_empty(group: u64) -> u64 {
    group & (group << 1) & HI
}

/// Bytes of `group` that are `EMPTY` or `DELETED`.
fn match_free(group: u64) -> u64 {
    group & HI
}

fn with_byte(group: u64, i: usize, byte: u8) -> u64 {
    let shift = i * 8;
    (group & !(0xFF << shift)) | (u64::from(byte) << shift)
}

fn hash(key: &[u8; 32]) -> u64 {
    let mut h = [0; 8];
    h.copy_from_slice(&key[..8]);
    u64::from_le_bytes(h)
}

fn key_words(key: &[u8; 32]) -> [u64; 4] {
    std::array::from_fn(|i| {
        let mut w = [0; 8];
        w.copy_from_slice(&key[i * 8..i * 8 + 8]);
        u64::from_le_bytes(w)
    })
}

/// Seven bits for the control byte, from bits the group index and the
/// shard do not use.
fn h2(h: u64) -> u8 {
    ((h >> 50) & 0x7F) as u8
}

/// What only the shard's writer changes.
struct Writer {
    /// Per level: how many `EMPTY` slots may still be used.
    growth: Vec<usize>,
    ext_free: Vec<u32>,
    ext_next: u32,
}

struct Shard<const W: usize, const X: usize> {
    levels: Box<[OnceLock<Level<W>>]>,
    /// Levels allocated so far.
    count: AtomicUsize,
    ext: Box<[OnceLock<Box<[Ext<X>]>>]>,
    writer: Mutex<Writer>,
    live: AtomicUsize,
}

impl<const W: usize, const X: usize> Shard<W, X> {
    fn ext_block(&self, index: u64) -> Option<&Ext<X>> {
        let index = usize::try_from(index).ok()?;
        self.ext
            .get(index / EXT_CHUNK)?
            .get()?
            .get(index % EXT_CHUNK)
    }

    /// Read the slot if it holds `key`, retrying while a writer moves it.
    fn read_cell(&self, cell: &Cell<W>, key: &[u64; 4]) -> Option<([u64; W], Option<[u64; X]>)> {
        loop {
            let s1 = cell.seq.load(Ordering::Acquire);
            if s1 & 1 == 1 {
                spin();
                continue;
            }
            let k: [u64; 4] = std::array::from_fn(|i| cell.key[i].load(Ordering::Relaxed));
            let mut out = None;
            if k == *key {
                let words: [u64; W] =
                    std::array::from_fn(|i| cell.words[i].load(Ordering::Relaxed));
                let e = cell.ext.load(Ordering::Relaxed);
                let ext = match e {
                    0 => None,
                    e => self
                        .ext_block(e - 1)
                        .map(|b| std::array::from_fn(|i| b.words[i].load(Ordering::Relaxed))),
                };
                out = Some((words, ext, e));
            }
            fence(Ordering::Acquire);
            if cell.seq.load(Ordering::Relaxed) != s1 {
                spin();
                continue;
            }
            return match out {
                // An extension index with no block cannot be read
                // consistently; it is never written.
                Some((_, None, e)) if e != 0 => None,
                Some((words, ext, _)) => Some((words, ext)),
                None => None,
            };
        }
    }

    fn find_in(&self, level: &Level<W>, h: u64, key: &[u64; 4]) -> Option<Found<W, X>> {
        let byte = h2(h);
        let mut pos = h as usize & level.mask;
        let mut stride = 0;
        loop {
            let group = level.ctrl[pos].load(Ordering::Acquire);
            let mut m = match_byte(group, byte);
            while m != 0 {
                let i = (m.trailing_zeros() / 8) as usize;
                m &= m - 1;
                let index = pos * 8 + i;
                let cell = &level.cells[index];
                if let Some((words, ext)) = self.read_cell(cell, key) {
                    return Some(Found {
                        at: At {
                            shard: 0,
                            level: 0,
                            index: index as u32,
                        },
                        words,
                        ext,
                        aux: cell.aux.load(Ordering::Relaxed),
                    });
                }
            }
            if match_empty(group) != 0 || stride == level.mask {
                return None;
            }
            stride += 1;
            pos = (pos + stride) & level.mask;
        }
    }

    fn find(&self, h: u64, key: &[u64; 4]) -> Option<Found<W, X>> {
        let count = self.count.load(Ordering::Acquire);
        for li in (0..count).rev() {
            let Some(level) = self.levels[li].get() else {
                continue;
            };
            if level.live.load(Ordering::Relaxed) == 0 {
                continue;
            }
            if let Some(mut found) = self.find_in(level, h, key) {
                found.at.level = li as u8;
                return Some(found);
            }
        }
        None
    }

    /// The first free slot on `h`'s probe path in `level`, and whether it
    /// is `EMPTY` (rather than `DELETED`).
    fn free_slot(level: &Level<W>, h: u64) -> Option<(usize, bool)> {
        let mut pos = h as usize & level.mask;
        let mut stride = 0;
        loop {
            let group = level.ctrl[pos].load(Ordering::Relaxed);
            let m = match_free(group);
            if m != 0 {
                let i = (m.trailing_zeros() / 8) as usize;
                let empty = ((group >> (i * 8)) & 0xFF) as u8 == EMPTY;
                return Some((pos * 8 + i, empty));
            }
            if stride == level.mask {
                return None;
            }
            stride += 1;
            pos = (pos + stride) & level.mask;
        }
    }

    fn set_ctrl(level: &Level<W>, index: usize, byte: u8) {
        let group = &level.ctrl[index / 8];
        let old = group.load(Ordering::Relaxed);
        group.store(with_byte(old, index % 8, byte), Ordering::Release);
    }

    fn write_cell(cell: &Cell<W>, key: &[u64; 4], words: &[u64; W], ext: u64, aux: Option<u64>) {
        let s = cell.seq.load(Ordering::Relaxed);
        cell.seq.store(s.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        for (a, v) in cell.key.iter().zip(key) {
            a.store(*v, Ordering::Relaxed);
        }
        for (a, v) in cell.words.iter().zip(words) {
            a.store(*v, Ordering::Relaxed);
        }
        cell.ext.store(ext, Ordering::Relaxed);
        if let Some(aux) = aux {
            cell.aux.store(aux, Ordering::Relaxed);
        }
        cell.seq.store(s.wrapping_add(2), Ordering::Release);
    }

    fn take_ext(&self, w: &mut Writer) -> Option<u32> {
        if let Some(i) = w.ext_free.pop() {
            return Some(i);
        }
        let i = w.ext_next;
        let chunk = self.ext.get(i as usize / EXT_CHUNK)?;
        let _ = chunk.get_or_init(|| {
            (0..EXT_CHUNK)
                .map(|_| Ext {
                    words: std::array::from_fn(|_| AtomicU64::new(0)),
                })
                .collect()
        });
        w.ext_next = i.checked_add(1)?;
        Some(i)
    }

    fn write_ext(&self, index: u32, ext: &[u64; X]) {
        if let Some(block) = self.ext_block(u64::from(index)) {
            for (a, v) in block.words.iter().zip(ext) {
                a.store(*v, Ordering::Relaxed);
            }
        }
    }
}

/// The table. `W` inline words per entry; `X` more in an extension block
/// for entries that need them.
pub(crate) struct Table<const W: usize, const X: usize> {
    shards: Box<[Shard<W, X>]>,
    /// log2 of the shard count.
    shard_bits: u32,
    /// Groups of eight slots in each shard's first level.
    base_groups: usize,
}

impl<const W: usize, const X: usize> std::fmt::Debug for Table<W, X> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Table")
            .field("shards", &self.shards.len())
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl<const W: usize, const X: usize> Table<W, X> {
    /// A table of `shards` shards (a power of two, at most 64) whose first
    /// levels hold `base` slots each (a power of two, at least 8), with
    /// room for `max` entries spread evenly (twice that in the worst
    /// spread; `max` is at most [`MAX_ENTRIES`]). Only the first level of
    /// each shard is allocated now.
    pub(crate) fn new(shards: usize, base: usize, max: usize) -> Self {
        let max = max.min(MAX_ENTRIES);
        let shards = shards.clamp(1, 64).next_power_of_two();
        let base_groups = (base.max(8).next_power_of_two()) / 8;
        let per_shard = (max.div_ceil(shards)).saturating_mul(2).max(1);
        let mut levels = 1;
        let mut room = base_groups * 8 * FILL_EIGHTHS / 8;
        while room < per_shard && levels < 32 {
            room += ((base_groups * 8) << levels) * FILL_EIGHTHS / 8;
            levels += 1;
        }
        let ext_chunks = per_shard.div_ceil(EXT_CHUNK);
        let shards = (0..shards)
            .map(|_| {
                let levels: Box<[OnceLock<Level<W>>]> =
                    (0..levels).map(|_| OnceLock::new()).collect();
                let _ = levels[0].set(Level::new(base_groups));
                Shard {
                    levels,
                    count: AtomicUsize::new(1),
                    ext: (0..if X == 0 { 0 } else { ext_chunks })
                        .map(|_| OnceLock::new())
                        .collect(),
                    writer: Mutex::new(Writer {
                        growth: vec![base_groups * 8 * FILL_EIGHTHS / 8],
                        ext_free: Vec::new(),
                        ext_next: 0,
                    }),
                    live: AtomicUsize::new(0),
                }
            })
            .collect::<Box<[_]>>();
        Table {
            shard_bits: shards.len().trailing_zeros(),
            shards,
            base_groups,
        }
    }

    fn shard_of(&self, h: u64) -> usize {
        if self.shard_bits == 0 {
            0
        } else {
            (h >> (64 - self.shard_bits)) as usize
        }
    }

    /// The entry for `key`. Takes no lock and writes nothing.
    pub(crate) fn get(&self, key: &[u8; 32]) -> Option<Found<W, X>> {
        let h = hash(key);
        let s = self.shard_of(h);
        let mut found = self.shards[s].find(h, &key_words(key))?;
        found.at.shard = s as u16;
        Some(found)
    }

    fn cell(&self, at: At) -> Option<(&Shard<W, X>, &Level<W>, &Cell<W>)> {
        let shard = self.shards.get(usize::from(at.shard))?;
        let level = shard.levels.get(usize::from(at.level))?.get()?;
        let cell = level.cells.get(at.index as usize)?;
        Some((shard, level, cell))
    }

    /// Raise the entry's `aux` word to at least `v`. Takes no lock. If the
    /// entry at `at` was removed and its slot reused meanwhile, the new
    /// entry's word is raised instead; callers keep only values for which
    /// that is harmless (a time that is already now).
    pub(crate) fn raise_aux(&self, at: At, v: u64) {
        if let Some((_, _, cell)) = self.cell(at) {
            let _ = cell.aux.fetch_max(v, Ordering::Relaxed);
        }
    }

    /// Put `key` in the table.
    pub(crate) fn insert(
        &self,
        key: &[u8; 32],
        words: &[u64; W],
        ext: Option<&[u64; X]>,
        aux: u64,
    ) -> Result<At, Refused> {
        let h = hash(key);
        let s = self.shard_of(h);
        let shard = &self.shards[s];
        let kw = key_words(key);
        let mut w = shard.writer.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(found) = shard.find(h, &kw) {
            return Err(Refused::Exists(At {
                shard: s as u16,
                ..found.at
            }));
        }
        let count = shard.count.load(Ordering::Relaxed);
        let mut target = None;
        for li in (0..count).rev() {
            let Some(level) = shard.levels[li].get() else {
                continue;
            };
            if let Some((index, empty)) = Shard::<W, X>::free_slot(level, h) {
                if !empty || w.growth[li] > 0 {
                    target = Some((li, index, empty));
                    break;
                }
            }
        }
        if target.is_none() && count < shard.levels.len() {
            let level = Level::new(self.base_groups << count);
            let growth = level.capacity() * FILL_EIGHTHS / 8;
            let _ = shard.levels[count].set(level);
            w.growth.push(growth);
            shard.count.store(count + 1, Ordering::Release);
            if let Some(level) = shard.levels[count].get() {
                target = Shard::<W, X>::free_slot(level, h).map(|(i, e)| (count, i, e));
            }
        }
        let Some((li, index, empty)) = target else {
            return Err(Refused::Full);
        };
        let ext_index = match ext {
            Some(ext) => {
                let i = shard.take_ext(&mut w).ok_or(Refused::Full)?;
                shard.write_ext(i, ext);
                u64::from(i) + 1
            }
            None => 0,
        };
        let Some(level) = shard.levels[li].get() else {
            return Err(Refused::Full);
        };
        Shard::<W, X>::write_cell(&level.cells[index], &kw, words, ext_index, Some(aux));
        if empty {
            w.growth[li] -= 1;
        }
        let _ = level.live.fetch_add(1, Ordering::Relaxed);
        let _ = shard.live.fetch_add(1, Ordering::Relaxed);
        Shard::<W, X>::set_ctrl(level, index, h2(h));
        Ok(At {
            shard: s as u16,
            level: li as u8,
            index: index as u32,
        })
    }

    /// Replace the words (and extension) of the entry at `at`, keeping its
    /// key and `aux`. Returns false if `at` holds no entry.
    pub(crate) fn update(&self, at: At, words: &[u64; W], ext: Option<&[u64; X]>) -> bool {
        let Some((shard, level, cell)) = self.cell(at) else {
            return false;
        };
        let mut w = shard.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let index = at.index as usize;
        if (level.ctrl[index / 8].load(Ordering::Relaxed) >> ((index % 8) * 8)) & 0x80 != 0 {
            return false;
        }
        let old = cell.ext.load(Ordering::Relaxed);
        let ext_index = match (ext, old) {
            (Some(ext), 0) => match shard.take_ext(&mut w) {
                Some(i) => {
                    shard.write_ext(i, ext);
                    u64::from(i) + 1
                }
                None => return false,
            },
            (Some(_), old) => old,
            (None, _) => 0,
        };
        // An extension block in place is rewritten under the slot's
        // sequence, so a reader of it retries.
        let s = cell.seq.load(Ordering::Relaxed);
        cell.seq.store(s.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        if let (Some(ext), true) = (ext, old != 0) {
            shard.write_ext((old - 1) as u32, ext);
        }
        for (a, v) in cell.words.iter().zip(words) {
            a.store(*v, Ordering::Relaxed);
        }
        cell.ext.store(ext_index, Ordering::Relaxed);
        cell.seq.store(s.wrapping_add(2), Ordering::Release);
        if ext.is_none() && old != 0 {
            w.ext_free.push((old - 1) as u32);
        }
        true
    }

    /// Remove the entry at `at`. Returns false if it holds none.
    pub(crate) fn remove(&self, at: At) -> bool {
        let Some((shard, level, cell)) = self.cell(at) else {
            return false;
        };
        let mut w = shard.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let index = at.index as usize;
        let group = level.ctrl[index / 8].load(Ordering::Relaxed);
        let byte = ((group >> ((index % 8) * 8)) & 0xFF) as u8;
        if byte & 0x80 != 0 {
            return false;
        }
        let old = cell.ext.load(Ordering::Relaxed);
        Shard::<W, X>::write_cell(cell, &[0; 4], &[0; W], 0, Some(0));
        if old != 0 {
            w.ext_free.push((old - 1) as u32);
        }
        // A group that still has an EMPTY byte never stopped a probe from
        // passing it, so the removed slot can be EMPTY again.
        let li = usize::from(at.level);
        if match_empty(group) != 0 {
            Shard::<W, X>::set_ctrl(level, index, EMPTY);
            w.growth[li] += 1;
        } else {
            Shard::<W, X>::set_ctrl(level, index, DELETED);
        }
        let _ = shard.live.fetch_sub(1, Ordering::Relaxed);
        if level.live.fetch_sub(1, Ordering::Relaxed) == 1 {
            // Nothing is left to find in the level, so no probe can miss an
            // entry when every slot becomes EMPTY.
            for group in level.ctrl.iter() {
                group.store(u64::MAX, Ordering::Release);
            }
            w.growth[li] = level.capacity() * FILL_EIGHTHS / 8;
        }
        true
    }

    /// The key and entry at `at`, if any.
    pub(crate) fn read_at(&self, at: At) -> Option<([u8; 32], Found<W, X>)> {
        let (shard, level, cell) = self.cell(at)?;
        let _w = shard.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let index = at.index as usize;
        let group = level.ctrl[index / 8].load(Ordering::Relaxed);
        if (group >> ((index % 8) * 8)) & 0x80 != 0 {
            return None;
        }
        let kw: [u64; 4] = std::array::from_fn(|i| cell.key[i].load(Ordering::Relaxed));
        let (words, ext) = shard.read_cell(cell, &kw)?;
        let mut key = [0; 32];
        for (chunk, w) in key.chunks_exact_mut(8).zip(kw) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
        Some((
            key,
            Found {
                at,
                words,
                ext,
                aux: cell.aux.load(Ordering::Relaxed),
            },
        ))
    }

    /// Every entry, one shard at a time with that shard's writer held.
    pub(crate) fn for_each(&self, mut f: impl FnMut([u8; 32], Found<W, X>)) {
        for (s, shard) in self.shards.iter().enumerate() {
            let _w = shard.writer.lock().unwrap_or_else(PoisonError::into_inner);
            let count = shard.count.load(Ordering::Relaxed);
            for li in 0..count {
                let Some(level) = shard.levels[li].get() else {
                    continue;
                };
                if level.live.load(Ordering::Relaxed) == 0 {
                    continue;
                }
                for (g, group) in level.ctrl.iter().enumerate() {
                    let group = group.load(Ordering::Relaxed);
                    let mut full = !group & HI;
                    while full != 0 {
                        let i = (full.trailing_zeros() / 8) as usize;
                        full &= full - 1;
                        let index = g * 8 + i;
                        let cell = &level.cells[index];
                        let kw: [u64; 4] =
                            std::array::from_fn(|i| cell.key[i].load(Ordering::Relaxed));
                        if let Some((words, ext)) = shard.read_cell(cell, &kw) {
                            let mut key = [0; 32];
                            for (chunk, w) in key.chunks_exact_mut(8).zip(kw) {
                                chunk.copy_from_slice(&w.to_le_bytes());
                            }
                            f(
                                key,
                                Found {
                                    at: At {
                                        shard: s as u16,
                                        level: li as u8,
                                        index: index as u32,
                                    },
                                    words,
                                    ext,
                                    aux: cell.aux.load(Ordering::Relaxed),
                                },
                            );
                        }
                    }
                }
            }
        }
    }

    /// Entries in the table.
    pub(crate) fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.live.load(Ordering::Relaxed))
            .sum()
    }

    /// Bytes allocated for slots, control bytes, and extension blocks.
    pub(crate) fn memory(&self) -> usize {
        let cell = std::mem::size_of::<Cell<W>>() + 1;
        let ext = std::mem::size_of::<Ext<X>>();
        self.shards
            .iter()
            .map(|shard| {
                let levels: usize = shard
                    .levels
                    .iter()
                    .filter_map(OnceLock::get)
                    .map(|l| l.capacity() * cell)
                    .sum();
                let exts = shard.ext.iter().filter(|c| c.get().is_some()).count();
                levels + exts * EXT_CHUNK * ext
            })
            .sum()
    }
}
