//! A table from 32-byte keys to fixed-size values, read without locks.
//!
//! Self-contained: it uses nothing else in the crate, so it can move to a
//! crate of its own (`dev/PLAN.md` D-055).
//!
//! - **Shards**, chosen by the key's top bits. One writer at a time per
//!   shard (a mutex only writers take); readers take no lock and write
//!   nothing.
//! - **Cells**: each entry lives in a cell of a per-shard pool, allocated in
//!   chunks as the shard fills and reused when entries are removed. A cell
//!   never moves, so its place ([`At`]) is stable while the entry exists.
//! - **Index**: an open-addressed array of groups, each eight control bytes
//!   in a `u64` (matched eight at a time) and the eight cell numbers they
//!   stand for. When the index fills, the writer builds a new one sized for
//!   the entries (from a set of sizes kept once allocated) and switches
//!   readers to it with one atomic store; a reader that misses checks that
//!   the index it used is still the current one, and probes again if not.
//!   A hit is always checked against the cell's key, so any index a reader
//!   holds can only cost it a retry, never a wrong answer.
//! - **Cells** are runs of atomic words read as a sequence lock: a reader
//!   copies the words and retries if a writer changed the cell's sequence
//!   meanwhile. Each cell also has one word outside the lock (`aux`) that
//!   readers may raise without a writer, such as a last-used time.
//! - **Extensions**: a value longer than the inline words keeps the rest in
//!   a block from a per-shard pool, read under the owning cell's sequence.
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
    atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering, fence},
};
#[cfg(not(all(nex_loom, test)))]
use std::sync::{
    Mutex,
    atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering, fence},
};

/// The control byte of an index slot never used since the index was built.
const EMPTY: u8 = 0xFF;
/// The control byte of an index slot whose entry was removed.
const DELETED: u8 = 0x80;
const LO: u64 = 0x0101_0101_0101_0101;
const HI: u64 = 0x8080_8080_8080_8080;
/// Cells and extension blocks are allocated in chunks: the first holds
/// `FIRST_CHUNK`, each next one twice the one before, up to `LAST_CHUNK`.
/// Small tables stay small; large ones keep few chunks, so the chunk list a
/// read goes through stays in the CPU cache.
#[cfg(not(all(nex_loom, test)))]
const FIRST_CHUNK: usize = 64;
#[cfg(not(all(nex_loom, test)))]
const LAST_CHUNK: usize = 1024;
#[cfg(all(nex_loom, test))]
const FIRST_CHUNK: usize = 2;
#[cfg(all(nex_loom, test))]
const LAST_CHUNK: usize = 4;
/// Doublings from the first chunk size to the last.
const DOUBLINGS: u32 = (LAST_CHUNK / FIRST_CHUNK).trailing_zeros();
/// Items in the chunks that grow, before the ones of the last size.
const GROWING: usize = FIRST_CHUNK * ((1 << DOUBLINGS) - 1);
/// An index is filled to at most this many sixteenths before it is
/// rebuilt; a rebuilt index starts at most half that full.
const FILL_SIXTEENTHS: usize = 14;
/// The most entries a table is sized for, which bounds what it sets aside
/// for cells and extension blocks it has not allocated yet.
pub(crate) const MAX_ENTRIES: usize = u32::MAX as usize;

/// The chunk that holds item `n`, and its place in it.
fn chunk_of(n: usize) -> (usize, usize) {
    if n < GROWING {
        let k = (usize::BITS - 1 - (n / FIRST_CHUNK + 1).leading_zeros()) as usize;
        (k, n - FIRST_CHUNK * ((1 << k) - 1))
    } else {
        let rest = n - GROWING;
        (DOUBLINGS as usize + rest / LAST_CHUNK, rest % LAST_CHUNK)
    }
}

/// Items in chunk `k`.
fn chunk_len(k: usize) -> usize {
    if k < DOUBLINGS as usize {
        FIRST_CHUNK << k
    } else {
        LAST_CHUNK
    }
}

/// Chunks that hold `n` items.
fn chunks_for(n: usize) -> usize {
    if n == 0 { 0 } else { chunk_of(n - 1).0 + 1 }
}

fn spin() {
    #[cfg(all(nex_loom, test))]
    loom::thread::yield_now();
    #[cfg(not(all(nex_loom, test)))]
    std::hint::spin_loop();
}

/// Where an entry is: shard and cell. Stable while the entry exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct At {
    shard: u16,
    index: u32,
}

impl At {
    /// As one `u64`, for keeping in other structures.
    pub(crate) fn to_u64(self) -> u64 {
        (u64::from(self.shard) << 32) | u64::from(self.index)
    }

    pub(crate) fn from_u64(v: u64) -> At {
        At {
            shard: (v >> 32) as u16,
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

    fn key(&self) -> [u64; 4] {
        std::array::from_fn(|i| self.key[i].load(Ordering::Relaxed))
    }
}

struct Ext<const X: usize> {
    words: [AtomicU64; X],
}

/// Eight index slots: their control bytes and the cells they stand for.
struct Group {
    ctrl: AtomicU64,
    cells: [AtomicU32; 8],
}

struct Index {
    groups: Box<[Group]>,
    /// Groups minus one (groups are a power of two).
    mask: usize,
}

impl Index {
    fn new(groups: usize) -> Self {
        Index {
            groups: (0..groups)
                .map(|_| Group {
                    ctrl: AtomicU64::new(u64::MAX),
                    cells: std::array::from_fn(|_| AtomicU32::new(0)),
                })
                .collect(),
            mask: groups - 1,
        }
    }

    fn capacity(&self) -> usize {
        self.groups.len() * 8
    }

    /// The first free slot on `h`'s probe path, and whether it is `EMPTY`
    /// (rather than `DELETED`).
    fn free_slot(&self, h: u64) -> Option<(usize, bool)> {
        let mut pos = h as usize & self.mask;
        let mut stride = 0;
        loop {
            let group = self.groups[pos].ctrl.load(Ordering::Relaxed);
            let m = match_free(group);
            if m != 0 {
                let i = (m.trailing_zeros() / 8) as usize;
                let empty = ((group >> (i * 8)) & 0xFF) as u8 == EMPTY;
                return Some((pos * 8 + i, empty));
            }
            if stride == self.mask {
                return None;
            }
            stride += 1;
            pos = (pos + stride) & self.mask;
        }
    }

    /// Point slot `slot` at `cell`. The cell number is stored before the
    /// control byte, which a reader loads first.
    fn set(&self, slot: usize, cell: u32, byte: u8) {
        let group = &self.groups[slot / 8];
        group.cells[slot % 8].store(cell, Ordering::Relaxed);
        set_ctrl(group, slot % 8, byte);
    }

    /// The slot on `h`'s probe path that stands for `cell`.
    fn slot_of(&self, h: u64, cell: u32) -> Option<usize> {
        let byte = h2(h);
        let mut pos = h as usize & self.mask;
        let mut stride = 0;
        loop {
            let group = &self.groups[pos];
            let ctrl = group.ctrl.load(Ordering::Relaxed);
            let mut m = match_byte(ctrl, byte);
            while m != 0 {
                let i = (m.trailing_zeros() / 8) as usize;
                m &= m - 1;
                if group.cells[i].load(Ordering::Relaxed) == cell {
                    return Some(pos * 8 + i);
                }
            }
            if match_empty(ctrl) != 0 || stride == self.mask {
                return None;
            }
            stride += 1;
            pos = (pos + stride) & self.mask;
        }
    }
}

fn set_ctrl(group: &Group, i: usize, byte: u8) {
    let old = group.ctrl.load(Ordering::Relaxed);
    group.ctrl.store(with_byte(old, i, byte), Ordering::Release);
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

fn hash_words(key: &[u64; 4]) -> u64 {
    key[0]
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

/// The most entries an index of `capacity` slots takes before a rebuild.
fn fill_limit(capacity: usize) -> usize {
    capacity * FILL_SIXTEENTHS / 16
}

/// What only the shard's writer changes.
struct Writer {
    /// The current index's size class.
    class: usize,
    /// How many `EMPTY` slots of the current index may still be used.
    growth: usize,
    /// Cells given back by removed entries.
    free: Vec<u32>,
    /// Cells handed out so far.
    next: u32,
    /// Which cells hold an entry.
    used: Vec<u64>,
    ext_free: Vec<u32>,
    ext_next: u32,
}

impl Writer {
    fn is_used(&self, cell: u32) -> bool {
        self.used
            .get(cell as usize / 64)
            .is_some_and(|w| w & (1 << (cell % 64)) != 0)
    }

    fn set_used(&mut self, cell: u32, used: bool) {
        let i = cell as usize / 64;
        if i >= self.used.len() {
            self.used.resize(i + 1, 0);
        }
        if used {
            self.used[i] |= 1 << (cell % 64);
        } else {
            self.used[i] &= !(1 << (cell % 64));
        }
    }
}

struct Shard<const W: usize, const X: usize> {
    cells: Box<[OnceLock<Box<[Cell<W>]>>]>,
    /// Indexes by size class, each twice the slots of the one before;
    /// allocated when first needed and kept.
    indexes: Box<[OnceLock<Index>]>,
    /// The current index: a generation (raised on every switch) above the
    /// size class in the low byte.
    state: AtomicU64,
    ext: Box<[OnceLock<Box<[Ext<X>]>>]>,
    writer: Mutex<Writer>,
    live: AtomicUsize,
}

impl<const W: usize, const X: usize> Shard<W, X> {
    fn cell(&self, index: u32) -> Option<&Cell<W>> {
        let (k, i) = chunk_of(index as usize);
        self.cells.get(k)?.get()?.get(i)
    }

    fn ext_block(&self, index: u64) -> Option<&Ext<X>> {
        let (k, i) = chunk_of(usize::try_from(index).ok()?);
        self.ext.get(k)?.get()?.get(i)
    }

    /// Read the cell if it holds `key`, retrying while a writer changes it.
    fn read_cell(&self, cell: &Cell<W>, key: &[u64; 4]) -> Option<([u64; W], Option<[u64; X]>)> {
        loop {
            let s1 = cell.seq.load(Ordering::Acquire);
            if s1 & 1 == 1 {
                spin();
                continue;
            }
            let k = cell.key();
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

    fn find_in(&self, index: &Index, h: u64, key: &[u64; 4]) -> Option<Found<W, X>> {
        let byte = h2(h);
        let mut pos = h as usize & index.mask;
        let mut stride = 0;
        loop {
            let group = &index.groups[pos];
            let ctrl = group.ctrl.load(Ordering::Acquire);
            let mut m = match_byte(ctrl, byte);
            while m != 0 {
                let i = (m.trailing_zeros() / 8) as usize;
                m &= m - 1;
                let n = group.cells[i].load(Ordering::Relaxed);
                let Some(cell) = self.cell(n) else {
                    continue;
                };
                if let Some((words, ext)) = self.read_cell(cell, key) {
                    return Some(Found {
                        at: At { shard: 0, index: n },
                        words,
                        ext,
                        aux: cell.aux.load(Ordering::Relaxed),
                    });
                }
            }
            if match_empty(ctrl) != 0 || stride == index.mask {
                return None;
            }
            stride += 1;
            pos = (pos + stride) & index.mask;
        }
    }

    fn find(&self, h: u64, key: &[u64; 4]) -> Option<Found<W, X>> {
        loop {
            let state = self.state.load(Ordering::Acquire);
            let index = self.indexes.get((state & 0xFF) as usize)?.get()?;
            if let Some(found) = self.find_in(index, h, key) {
                return Some(found);
            }
            // A miss counts only if the index is still the current one: a
            // writer may have switched to a new index, and be rebuilding
            // the old one, since this probe began.
            if self.state.load(Ordering::Acquire) == state {
                return None;
            }
        }
    }

    fn current(&self, w: &Writer) -> Option<&Index> {
        self.indexes.get(w.class)?.get()
    }

    /// Rebuild the index for `need` entries into a size class other than
    /// the current one, and switch readers to it. Returns false when no
    /// size class can hold them.
    fn rebuild(&self, w: &mut Writer, need: usize) -> bool {
        let base = self.indexes[0].get().map_or(8, Index::capacity);
        let fits = |class: usize| fill_limit(base << class) / 2 >= need;
        let Some(mut class) = (0..self.indexes.len()).find(|c| fits(*c)) else {
            return false;
        };
        if class == w.class {
            class += 1;
        }
        let Some(slot) = self.indexes.get(class) else {
            return false;
        };
        let target = slot.get_or_init(|| Index::new((base << class) / 8));
        let Some(old) = self.current(w) else {
            return false;
        };
        // Readers still probing `target` from an earlier switch see it
        // change under them and probe again once they find the state moved.
        for group in target.groups.iter() {
            group.ctrl.store(u64::MAX, Ordering::Release);
        }
        let mut used = 0;
        for group in old.groups.iter() {
            let ctrl = group.ctrl.load(Ordering::Relaxed);
            let mut full = !ctrl & HI;
            while full != 0 {
                let i = (full.trailing_zeros() / 8) as usize;
                full &= full - 1;
                let n = group.cells[i].load(Ordering::Relaxed);
                let Some(cell) = self.cell(n) else {
                    continue;
                };
                let h = hash_words(&cell.key());
                if let Some((slot, _)) = target.free_slot(h) {
                    target.set(slot, n, h2(h));
                    used += 1;
                }
            }
        }
        let state = self.state.load(Ordering::Relaxed);
        let generation = (state >> 8).wrapping_add(1);
        self.state
            .store((generation << 8) | class as u64, Ordering::Release);
        w.class = class;
        w.growth = fill_limit(target.capacity()).saturating_sub(used);
        true
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

    fn take_cell(&self, w: &mut Writer) -> Option<u32> {
        if let Some(i) = w.free.pop() {
            return Some(i);
        }
        let i = w.next;
        let k = chunk_of(i as usize).0;
        let chunk = self.cells.get(k)?;
        let _ = chunk.get_or_init(|| (0..chunk_len(k)).map(|_| Cell::new()).collect());
        w.next = i.checked_add(1)?;
        Some(i)
    }

    fn take_ext(&self, w: &mut Writer) -> Option<u32> {
        if let Some(i) = w.ext_free.pop() {
            return Some(i);
        }
        let i = w.ext_next;
        let k = chunk_of(i as usize).0;
        let chunk = self.ext.get(k)?;
        let _ = chunk.get_or_init(|| {
            (0..chunk_len(k))
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
    /// indexes have `base` slots each (a power of two, at least 8), with
    /// room for `max` entries spread evenly (twice that in the worst
    /// spread; `max` is at most [`MAX_ENTRIES`]). Only the first index of
    /// each shard is allocated now; cells are allocated as entries arrive.
    pub(crate) fn new(shards: usize, base: usize, max: usize) -> Self {
        let max = max.min(MAX_ENTRIES);
        let shards = shards.clamp(1, 64).next_power_of_two();
        let base = base.max(8).next_power_of_two();
        let per_shard = (max.div_ceil(shards))
            .saturating_mul(2)
            .clamp(1, MAX_ENTRIES);
        // Size classes up to one that holds `per_shard` entries just after
        // a rebuild, and one more, so a rebuild always has a class to go to.
        let mut classes = 1;
        while fill_limit(base << (classes - 1)) / 2 < per_shard && classes < 40 {
            classes += 1;
        }
        classes += 1;
        let chunks = chunks_for(per_shard);
        let shards = (0..shards)
            .map(|_| {
                let indexes: Box<[OnceLock<Index>]> =
                    (0..classes).map(|_| OnceLock::new()).collect();
                let _ = indexes[0].set(Index::new(base / 8));
                Shard {
                    cells: (0..chunks).map(|_| OnceLock::new()).collect(),
                    indexes,
                    state: AtomicU64::new(0),
                    ext: (0..if X == 0 { 0 } else { chunks })
                        .map(|_| OnceLock::new())
                        .collect(),
                    writer: Mutex::new(Writer {
                        class: 0,
                        growth: fill_limit(base),
                        free: Vec::new(),
                        next: 0,
                        used: Vec::new(),
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
        let kw = key_words(key);
        let h = hash_words(&kw);
        let s = self.shard_of(h);
        let mut found = self.shards[s].find(h, &kw)?;
        found.at.shard = s as u16;
        Some(found)
    }

    fn cell(&self, at: At) -> Option<(&Shard<W, X>, &Cell<W>)> {
        let shard = self.shards.get(usize::from(at.shard))?;
        let cell = shard.cell(at.index)?;
        Some((shard, cell))
    }

    /// Raise the entry's `aux` word to at least `v`. Takes no lock. If the
    /// entry at `at` was removed and its cell reused meanwhile, the new
    /// entry's word is raised instead; callers keep only values for which
    /// that is harmless (a time that is already now).
    pub(crate) fn raise_aux(&self, at: At, v: u64) {
        if let Some((_, cell)) = self.cell(at) {
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
        let kw = key_words(key);
        let h = hash_words(&kw);
        let s = self.shard_of(h);
        let shard = &self.shards[s];
        let mut w = shard.writer.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(found) = shard.find(h, &kw) {
            return Err(Refused::Exists(At {
                shard: s as u16,
                ..found.at
            }));
        }
        // Room in the index first, so a refusal leaves nothing taken.
        let slot = match shard.current(&w).and_then(|i| i.free_slot(h)) {
            Some((slot, empty)) if !empty || w.growth > 0 => Some((slot, empty)),
            _ => None,
        };
        let (slot, empty) = match slot {
            Some(slot) => slot,
            None => {
                let need = shard.live.load(Ordering::Relaxed) + 1;
                if !shard.rebuild(&mut w, need) {
                    return Err(Refused::Full);
                }
                shard
                    .current(&w)
                    .and_then(|i| i.free_slot(h))
                    .ok_or(Refused::Full)?
            }
        };
        let n = shard.take_cell(&mut w).ok_or(Refused::Full)?;
        let ext_index = match ext {
            Some(ext) => match shard.take_ext(&mut w) {
                Some(i) => {
                    shard.write_ext(i, ext);
                    u64::from(i) + 1
                }
                None => {
                    w.free.push(n);
                    return Err(Refused::Full);
                }
            },
            None => 0,
        };
        let (Some(cell), Some(index)) = (shard.cell(n), shard.current(&w)) else {
            return Err(Refused::Full);
        };
        Shard::<W, X>::write_cell(cell, &kw, words, ext_index, Some(aux));
        index.set(slot, n, h2(h));
        w.set_used(n, true);
        if empty {
            w.growth -= 1;
        }
        let _ = shard.live.fetch_add(1, Ordering::Relaxed);
        Ok(At {
            shard: s as u16,
            index: n,
        })
    }

    /// Replace the words (and extension) of the entry at `at`, keeping its
    /// key and `aux`. Returns false if `at` holds no entry.
    pub(crate) fn update(&self, at: At, words: &[u64; W], ext: Option<&[u64; X]>) -> bool {
        let Some((shard, cell)) = self.cell(at) else {
            return false;
        };
        let mut w = shard.writer.lock().unwrap_or_else(PoisonError::into_inner);
        if !w.is_used(at.index) {
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
        // An extension block in place is rewritten under the cell's
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
        let Some((shard, cell)) = self.cell(at) else {
            return false;
        };
        let mut w = shard.writer.lock().unwrap_or_else(PoisonError::into_inner);
        if !w.is_used(at.index) {
            return false;
        }
        let h = hash_words(&cell.key());
        let old = cell.ext.load(Ordering::Relaxed);
        // The cell is cleared before its index slot, so a reader that still
        // reaches it finds another key and misses.
        Shard::<W, X>::write_cell(cell, &[0; 4], &[0; W], 0, Some(0));
        if old != 0 {
            w.ext_free.push((old - 1) as u32);
        }
        if let Some((index, slot)) = shard
            .current(&w)
            .and_then(|index| Some((index, index.slot_of(h, at.index)?)))
        {
            let group = &index.groups[slot / 8];
            // A group that still has an EMPTY byte never stopped a probe
            // from passing it, so the slot can be EMPTY again.
            if match_empty(group.ctrl.load(Ordering::Relaxed)) != 0 {
                set_ctrl(group, slot % 8, EMPTY);
                w.growth += 1;
            } else {
                set_ctrl(group, slot % 8, DELETED);
            }
        }
        w.set_used(at.index, false);
        w.free.push(at.index);
        let _ = shard.live.fetch_sub(1, Ordering::Relaxed);
        true
    }

    /// The key and entry at `at`, if any.
    pub(crate) fn read_at(&self, at: At) -> Option<([u8; 32], Found<W, X>)> {
        let (shard, cell) = self.cell(at)?;
        let w = shard.writer.lock().unwrap_or_else(PoisonError::into_inner);
        if !w.is_used(at.index) {
            return None;
        }
        let kw = cell.key();
        let (words, ext) = shard.read_cell(cell, &kw)?;
        Some((
            key_bytes(&kw),
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
            let w = shard.writer.lock().unwrap_or_else(PoisonError::into_inner);
            for (word_index, word) in w.used.iter().enumerate() {
                let mut bits = *word;
                while bits != 0 {
                    let n = (word_index * 64) as u32 + bits.trailing_zeros();
                    bits &= bits - 1;
                    let Some(cell) = shard.cell(n) else {
                        continue;
                    };
                    let kw = cell.key();
                    if let Some((words, ext)) = shard.read_cell(cell, &kw) {
                        f(
                            key_bytes(&kw),
                            Found {
                                at: At {
                                    shard: s as u16,
                                    index: n,
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

    /// Entries in the table.
    pub(crate) fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.live.load(Ordering::Relaxed))
            .sum()
    }

    /// Bytes allocated for cells, indexes, extension blocks, and the
    /// writers' bookkeeping.
    pub(crate) fn memory(&self) -> usize {
        let cell = std::mem::size_of::<Cell<W>>();
        let group = std::mem::size_of::<Group>();
        let ext = std::mem::size_of::<Ext<X>>();
        self.shards
            .iter()
            .map(|shard| {
                let cells: usize = shard
                    .cells
                    .iter()
                    .filter_map(OnceLock::get)
                    .map(|c| c.len())
                    .sum();
                let indexes: usize = shard
                    .indexes
                    .iter()
                    .filter_map(OnceLock::get)
                    .map(|i| i.groups.len() * group)
                    .sum();
                let exts: usize = shard
                    .ext
                    .iter()
                    .filter_map(OnceLock::get)
                    .map(|c| c.len())
                    .sum();
                let w = shard.writer.lock().unwrap_or_else(PoisonError::into_inner);
                let books =
                    w.free.capacity() * 4 + w.used.capacity() * 8 + w.ext_free.capacity() * 4;
                cells * cell + indexes + exts * ext + books
            })
            .sum()
    }
}

fn key_bytes(kw: &[u64; 4]) -> [u8; 32] {
    let mut key = [0; 32];
    for (chunk, w) in key.chunks_exact_mut(8).zip(kw) {
        chunk.copy_from_slice(&w.to_le_bytes());
    }
    key
}
