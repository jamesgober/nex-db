//! Recent committed records, kept for shipping to read replicas.
//!
//! A commit's record is already in memory as an `Arc<[u8]>` when it is
//! applied; once the database has shipped once, the apply step keeps a
//! clone of that `Arc` here, so shipping recent commits reads no file and
//! copies nothing at commit time. The buffer holds at most
//! [`SHIP_BUFFER`] bytes of records and drops the oldest past it; a
//! replica further behind is sent records read from the log instead.
//!
//! Cost: none until the first [`Database::ship`](crate::Database::ship);
//! after it, one lock and one `Arc` clone per commit, and up to
//! [`SHIP_BUFFER`] bytes of memory held.

use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
};

use super::record::Seq;

/// Bytes of records the buffer holds at most.
pub(crate) const SHIP_BUFFER: usize = 32 * 1024 * 1024;

#[derive(Debug, Default)]
struct Held {
    records: VecDeque<(Seq, Arc<[u8]>)>,
    bytes: usize,
}

/// The buffer of recent records.
#[derive(Debug, Default)]
pub(crate) struct ShipBuffer {
    on: AtomicBool,
    held: Mutex<Held>,
}

impl ShipBuffer {
    /// Start keeping records: from the next commit on.
    pub(crate) fn start(&self) {
        self.on.store(true, Ordering::Release);
    }

    /// Keep the record of commit `seq`, called in commit order. Nothing
    /// until [`start`](Self::start).
    pub(crate) fn push(&self, seq: Seq, record: &Arc<[u8]>) {
        if !self.on.load(Ordering::Acquire) {
            return;
        }
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        // A gap (a record kept before a restart of the buffer) is never
        // bridged: the buffer only ever holds consecutive records.
        if held
            .records
            .back()
            .is_some_and(|(last, _)| *last + 1 != seq)
        {
            held.records.clear();
            held.bytes = 0;
        }
        held.bytes += record.len();
        held.records.push_back((seq, Arc::clone(record)));
        while held.bytes > SHIP_BUFFER && held.records.len() > 1 {
            if let Some((_, old)) = held.records.pop_front() {
                held.bytes -= old.len();
            }
        }
    }

    /// The records from `from` on, if the buffer holds `from` itself, in
    /// order; `None` when `from` is older than the buffer (or newer than
    /// its last record).
    pub(crate) fn from(&self, from: Seq) -> Option<Vec<(Seq, Arc<[u8]>)>> {
        let held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let first = held.records.front()?.0;
        let index = usize::try_from(from.checked_sub(first)?).ok()?;
        if index >= held.records.len() {
            return None;
        }
        Some(held.records.iter().skip(index).cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(len: usize) -> Arc<[u8]> {
        vec![7u8; len].into()
    }

    #[test]
    fn test_nothing_is_kept_before_start() {
        let buffer = ShipBuffer::default();
        buffer.push(1, &record(10));
        assert!(buffer.from(1).is_none());
        buffer.start();
        buffer.push(2, &record(10));
        buffer.push(3, &record(10));
        let got: Vec<Seq> = buffer.from(2).unwrap().iter().map(|(s, _)| *s).collect();
        assert_eq!(got, [2, 3]);
        assert_eq!(buffer.from(3).unwrap().len(), 1);
        assert!(buffer.from(1).is_none() && buffer.from(4).is_none());
    }

    #[test]
    fn test_the_oldest_records_go_past_the_bound_and_a_gap_clears() {
        let buffer = ShipBuffer::default();
        buffer.start();
        let big = SHIP_BUFFER / 4 + 1;
        for seq in 1..=5 {
            buffer.push(seq, &record(big));
        }
        // Four would pass the bound: the oldest two are gone.
        assert!(buffer.from(2).is_none());
        assert_eq!(buffer.from(3).unwrap().len(), 3);
        buffer.push(9, &record(1));
        assert!(buffer.from(5).is_none());
        assert_eq!(buffer.from(9).unwrap().len(), 1);
    }
}
