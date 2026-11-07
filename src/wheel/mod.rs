//! A hierarchical timer wheel: insert and cancel in constant time, and an
//! advance that visits only slots with something due.
//!
//! Self-contained: it uses nothing else in the crate, so it can move to a
//! crate of its own (`dev/PLAN.md` D-055).
//!
//! Six levels of 64 slots. A timer goes in the level of the highest base-64
//! digit in which its tick differs from the current tick, so every timer in
//! a lower level is due before any in a higher one; advancing past a slot of
//! a higher level moves its timers down. Ticks are whole multiples of the
//! tick length, and a timer is never reported before its time (a time
//! beyond the wheel's span, 64^6 ticks, is reported at the span's end, and
//! the caller sets it again).

// Not every caller uses every call (the benchmarks include this module on
// its own).
#![allow(dead_code)]

const LEVELS: usize = 6;
const SLOTS: usize = 64;
/// Ticks the wheel spans.
const SPAN: u64 = 1 << (6 * LEVELS);
const NIL: u32 = u32::MAX;
/// The list of timers already due when set.
const PENDING: usize = LEVELS * SLOTS;

/// A timer that was set, for [`Wheel::cancel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Timer {
    index: u32,
    generation: u32,
}

#[derive(Debug)]
struct Node<T> {
    tick: u64,
    prev: u32,
    next: u32,
    /// The list the node is in, or `NIL` when free.
    list: u32,
    generation: u32,
    value: Option<T>,
}

/// The wheel. `T` is what a timer carries back when it fires.
#[derive(Debug)]
pub(crate) struct Wheel<T> {
    tick_ms: u64,
    /// The current tick: everything due at or before it has been reported.
    elapsed: u64,
    heads: Vec<u32>,
    occupied: [u64; LEVELS],
    nodes: Vec<Node<T>>,
    free: u32,
    len: usize,
}

fn level_for(elapsed: u64, tick: u64) -> usize {
    let masked = ((elapsed ^ tick) | (SLOTS as u64 - 1)).min(SPAN - 1);
    let significant = 63 - masked.leading_zeros() as usize;
    significant / 6
}

fn slot_range(level: usize) -> u64 {
    1 << (6 * level)
}

impl<T> Wheel<T> {
    /// A wheel whose ticks are `tick_ms` long, starting at `now_ms`.
    pub(crate) fn new(tick_ms: u64, now_ms: u64) -> Self {
        let tick_ms = tick_ms.max(1);
        Wheel {
            tick_ms,
            elapsed: now_ms / tick_ms,
            heads: vec![NIL; PENDING + 1],
            occupied: [0; LEVELS],
            nodes: Vec::new(),
            free: NIL,
            len: 0,
        }
    }

    /// Timers set and not yet fired or cancelled.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Set a timer for `due_ms` carrying `value`.
    pub(crate) fn insert(&mut self, due_ms: u64, value: T) -> Timer {
        // Round up: a timer never fires early. Past the span it fires at the
        // span's end.
        let tick = due_ms.div_ceil(self.tick_ms).min(self.elapsed + SPAN - 1);
        let index = if self.free == NIL {
            self.nodes.push(Node {
                tick,
                prev: NIL,
                next: NIL,
                list: NIL,
                generation: 0,
                value: Some(value),
            });
            (self.nodes.len() - 1) as u32
        } else {
            let index = self.free;
            let node = &mut self.nodes[index as usize];
            self.free = node.next;
            node.tick = tick;
            node.value = Some(value);
            index
        };
        self.len += 1;
        self.place(index);
        Timer {
            index,
            generation: self.nodes[index as usize].generation,
        }
    }

    /// Remove a timer before it fires, returning its value.
    pub(crate) fn cancel(&mut self, timer: Timer) -> Option<T> {
        let node = self.nodes.get(timer.index as usize)?;
        if node.generation != timer.generation || node.list == NIL {
            return None;
        }
        self.unlink(timer.index);
        self.len -= 1;
        self.release(timer.index)
    }

    /// Report every timer due at or before `now_ms` to `fire`, in tick order.
    pub(crate) fn advance(&mut self, now_ms: u64, mut fire: impl FnMut(T)) {
        let now = now_ms / self.tick_ms;
        loop {
            // Timers that were already due when set.
            while self.heads[PENDING] != NIL {
                let index = self.heads[PENDING];
                self.unlink(index);
                self.len -= 1;
                if let Some(value) = self.release(index) {
                    fire(value);
                }
            }
            let Some((level, slot, deadline)) = self.next_expiration() else {
                break;
            };
            if deadline > now {
                break;
            }
            self.elapsed = self.elapsed.max(deadline);
            let list = level * SLOTS + slot;
            let mut index = self.heads[list];
            self.heads[list] = NIL;
            self.occupied[level] &= !(1 << slot);
            while index != NIL {
                let next = self.nodes[index as usize].next;
                self.nodes[index as usize].list = NIL;
                if self.nodes[index as usize].tick <= self.elapsed {
                    self.len -= 1;
                    if let Some(value) = self.release(index) {
                        fire(value);
                    }
                } else {
                    self.place(index);
                }
                index = next;
            }
        }
        self.elapsed = self.elapsed.max(now);
    }

    /// The earliest slot with timers, and the tick it starts at.
    fn next_expiration(&self) -> Option<(usize, usize, u64)> {
        for level in 0..LEVELS {
            let occupied = self.occupied[level];
            if occupied == 0 {
                continue;
            }
            let range = slot_range(level);
            let now_slot = (self.elapsed / range) % SLOTS as u64;
            let zeros = u64::from(occupied.rotate_right(now_slot as u32).trailing_zeros());
            let slot = ((now_slot + zeros) % SLOTS as u64) as usize;
            let level_range = range * SLOTS as u64;
            let start = self.elapsed & !(level_range - 1);
            let mut deadline = start + slot as u64 * range;
            if deadline <= self.elapsed && level > 0 {
                // A slot behind the current one only happens at the top
                // level, for a time beyond the span.
                deadline += level_range;
            }
            return Some((level, slot, deadline.max(self.elapsed)));
        }
        None
    }

    fn place(&mut self, index: u32) {
        let elapsed = self.elapsed;
        let node = &mut self.nodes[index as usize];
        if node.tick <= elapsed {
            self.link(index, PENDING);
            return;
        }
        let tick = node.tick.min(elapsed + SPAN - 1);
        let level = level_for(elapsed, tick);
        let slot = ((tick >> (6 * level)) % SLOTS as u64) as usize;
        self.occupied[level] |= 1 << slot;
        self.link(index, level * SLOTS + slot);
    }

    fn link(&mut self, index: u32, list: usize) {
        let head = self.heads[list];
        {
            let node = &mut self.nodes[index as usize];
            node.prev = NIL;
            node.next = head;
            node.list = list as u32;
        }
        if head != NIL {
            self.nodes[head as usize].prev = index;
        }
        self.heads[list] = index;
    }

    fn unlink(&mut self, index: u32) {
        let (prev, next, list) = {
            let node = &self.nodes[index as usize];
            (node.prev, node.next, node.list as usize)
        };
        if prev == NIL {
            self.heads[list] = next;
            if next == NIL && list < PENDING {
                self.occupied[list / SLOTS] &= !(1 << (list % SLOTS));
            }
        } else {
            self.nodes[prev as usize].next = next;
        }
        if next != NIL {
            self.nodes[next as usize].prev = prev;
        }
        self.nodes[index as usize].list = NIL;
    }

    /// Free the node, returning its value (every linked node has one).
    fn release(&mut self, index: u32) -> Option<T> {
        let free = self.free;
        let node = &mut self.nodes[index as usize];
        node.generation = node.generation.wrapping_add(1);
        node.list = NIL;
        node.next = free;
        self.free = index;
        node.value.take()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn test_fires_at_its_time_never_before() {
        let mut wheel = Wheel::new(1000, 0);
        let _ = wheel.insert(2500, "a");
        let mut out = Vec::new();
        wheel.advance(2999, |v| out.push(v));
        assert!(out.is_empty());
        wheel.advance(3000, |v| out.push(v));
        assert_eq!(out, ["a"]);
        assert_eq!(wheel.len(), 0);
    }

    #[test]
    fn test_due_when_set_fires_on_next_advance() {
        let mut wheel = Wheel::new(1000, 10_000);
        let _ = wheel.insert(5_000, 1);
        let mut out = Vec::new();
        wheel.advance(10_000, |v| out.push(v));
        assert_eq!(out, [1]);
    }

    #[test]
    fn test_cancel_removes_and_stale_handle_does_nothing() {
        let mut wheel = Wheel::new(1, 0);
        let a = wheel.insert(100, 'a');
        let b = wheel.insert(100, 'b');
        assert_eq!(wheel.cancel(a), Some('a'));
        assert_eq!(wheel.cancel(a), None);
        let c = wheel.insert(50, 'c');
        // The freed node is reused; the old handle stays dead.
        assert_eq!(wheel.cancel(a), None);
        let mut out = Vec::new();
        wheel.advance(1000, |v| out.push(v));
        assert_eq!(out, ['c', 'b']);
        assert_eq!(wheel.cancel(b), None);
        assert_eq!(wheel.cancel(c), None);
    }

    #[test]
    fn test_beyond_the_span_fires_at_its_end() {
        let mut wheel = Wheel::new(1, 0);
        let _ = wheel.insert(u64::MAX, ());
        let mut fired = 0;
        wheel.advance(SPAN - 2, |()| fired += 1);
        assert_eq!(fired, 0);
        wheel.advance(SPAN, |()| fired += 1);
        assert_eq!(fired, 1);
    }

    /// Random times, cancels, and advances against a sorted map.
    #[test]
    fn test_matches_a_sorted_map() {
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut rand = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut wheel = Wheel::new(1000, 0);
        let mut model: BTreeMap<(u64, u64), Timer> = BTreeMap::new();
        let mut now = 0u64;
        for id in 0..20_000u64 {
            match rand() % 10 {
                0..=5 => {
                    // Spread over seconds to months.
                    let span = [10_000, 5_000_000, 3_000_000_000][(rand() % 3) as usize];
                    let due = now + rand() % span;
                    let timer = wheel.insert(due, (due, id));
                    let _ = model.insert((due, id), timer);
                }
                6 => {
                    if let Some((&k, &timer)) = model.iter().nth((rand() % 7) as usize) {
                        assert_eq!(wheel.cancel(timer), Some(k));
                        let _ = model.remove(&k);
                    }
                }
                _ => {
                    now += rand() % [2_000, 600_000, 90_000_000][(rand() % 3) as usize];
                    let mut fired = Vec::new();
                    wheel.advance(now, |v| fired.push(v));
                    let tick_now = now / 1000;
                    let due: Vec<(u64, u64)> = model
                        .keys()
                        .copied()
                        .filter(|(d, _)| d.div_ceil(1000) <= tick_now)
                        .collect();
                    for k in &due {
                        let _ = model.remove(k);
                    }
                    fired.sort_unstable();
                    assert_eq!(fired, due, "at {now}");
                }
            }
            assert_eq!(wheel.len(), model.len());
        }
    }
}
