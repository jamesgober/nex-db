//! The ordering half of the commit pipeline: the group writer, the
//! turnstile that applies commits in sequence order, and the visible mark.
//!
//! Generic over what is written and how it is applied, so a loom model
//! checks it on its own: `RUSTFLAGS="--cfg nex_loom" cargo test --release --lib
//! loom`.

use std::sync::PoisonError;

#[cfg(all(nex_loom, test))]
use loom::sync::{
    Condvar, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
#[cfg(not(all(nex_loom, test)))]
use std::sync::{
    Condvar, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

/// Why a commit stopped.
#[derive(Debug)]
pub(crate) enum Stop<E> {
    /// The pipeline halted after an earlier failure.
    Halted,
    /// This commit's own write or apply failed; the pipeline is now halted.
    Failed(E),
}

/// Items waiting for the writer, and how far the log is durable.
#[derive(Debug)]
struct Group<B> {
    /// Items in sequence order, not yet written.
    pending: Vec<(u64, B)>,
    /// A commit is writing and syncing a batch.
    writing: bool,
    /// Every item up to this sequence number is on stable storage.
    durable: u64,
}

/// The writer's queue, the apply turn, and the visible mark.
#[derive(Debug)]
pub(crate) struct Turnstile<B> {
    group: Mutex<Group<B>>,
    /// Woken when a batch is durable or the pipeline halts.
    written: Condvar,
    /// The last applied sequence number; commits apply in turn behind it.
    applied: Mutex<u64>,
    /// Woken when `applied` moves or the pipeline halts.
    turn: Condvar,
    /// The highest sequence number applied: what readers see.
    visible: AtomicU64,
    /// Set after a failed write or apply: no further commits.
    halted: AtomicBool,
}

impl<B> Turnstile<B> {
    pub(crate) fn new() -> Self {
        Turnstile {
            group: Mutex::new(Group {
                pending: Vec::new(),
                writing: false,
                durable: 0,
            }),
            written: Condvar::new(),
            applied: Mutex::new(0),
            turn: Condvar::new(),
            visible: AtomicU64::new(0),
            halted: AtomicBool::new(false),
        }
    }

    /// After recovery: everything through `last` is durable, applied, and
    /// visible.
    pub(crate) fn start_at(&self, last: u64) {
        *self.applied.lock().unwrap_or_else(PoisonError::into_inner) = last;
        self.group
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .durable = last;
        self.visible.store(last, Ordering::Release);
    }

    /// The highest sequence number readers may see. A reader that loads it
    /// sees every apply up to it.
    pub(crate) fn visible(&self) -> u64 {
        self.visible.load(Ordering::Acquire)
    }

    /// True after a failed write or apply.
    pub(crate) fn halted(&self) -> bool {
        self.halted.load(Ordering::Acquire)
    }

    /// Queue `item` for the writer. Callers queue in sequence order (under
    /// their sequencer lock).
    pub(crate) fn queue(&self, seq: u64, item: B) {
        self.group
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pending
            .push((seq, item));
    }

    /// Return once the item at `seq` is on stable storage. A commit that
    /// finds no writer at work becomes it: it takes every queued item and
    /// hands them to `write` (append in order, then sync once) outside the
    /// lock. A failed write is never retried and halts the pipeline.
    pub(crate) fn make_durable<E>(
        &self,
        seq: u64,
        mut write: impl FnMut(&[(u64, B)]) -> Result<(), E>,
    ) -> Result<(), Stop<E>> {
        let mut group = self.group.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if group.durable >= seq {
                return Ok(());
            }
            if self.halted() {
                return Err(Stop::Halted);
            }
            if group.writing {
                group = self
                    .written
                    .wait(group)
                    .unwrap_or_else(PoisonError::into_inner);
                continue;
            }
            let batch = std::mem::take(&mut group.pending);
            let Some(&(last, _)) = batch.last() else {
                // Not durable, not queued, no writer: only a halt does this.
                return Err(Stop::Halted);
            };
            group.writing = true;
            drop(group);

            let written = write(&batch);

            group = self.group.lock().unwrap_or_else(PoisonError::into_inner);
            group.writing = false;
            if let Err(err) = written {
                drop(group);
                self.halt();
                return Err(Stop::Failed(err));
            }
            group.durable = last;
            self.written.notify_all();
        }
    }

    /// Wait for the commit before `seq` to apply, run `apply`, then make
    /// `seq` visible. A failed apply halts the pipeline.
    pub(crate) fn complete<E>(
        &self,
        seq: u64,
        apply: impl FnOnce() -> Result<(), E>,
    ) -> Result<(), Stop<E>> {
        let mut applied = self.applied.lock().unwrap_or_else(PoisonError::into_inner);
        while *applied + 1 != seq {
            if self.halted() {
                return Err(Stop::Halted);
            }
            applied = self
                .turn
                .wait(applied)
                .unwrap_or_else(PoisonError::into_inner);
        }
        if self.halted() {
            return Err(Stop::Halted);
        }
        if let Err(err) = apply() {
            drop(applied);
            self.halt();
            return Err(Stop::Failed(err));
        }
        *applied = seq;
        self.visible.store(seq, Ordering::Release);
        drop(applied);
        self.turn.notify_all();
        Ok(())
    }

    /// Stop every later commit and wake every waiting one, so it fails
    /// instead of waiting for an item that will not be written or applied.
    /// Called with neither lock held.
    pub(crate) fn halt(&self) {
        self.halted.store(true, Ordering::Release);
        {
            let _group = self.group.lock().unwrap_or_else(PoisonError::into_inner);
            self.written.notify_all();
        }
        let _applied = self.applied.lock().unwrap_or_else(PoisonError::into_inner);
        self.turn.notify_all();
    }
}

/// Models of the writer, the turn, and the visible mark under every
/// interleaving loom explores.
#[cfg(all(nex_loom, test))]
mod models {
    use loom::sync::{Arc, Mutex, atomic::AtomicBool};

    use super::*;

    /// One commit: number it under the sequencer lock, make it durable,
    /// apply it in turn.
    fn commit(
        t: &Turnstile<u64>,
        sequencer: &Mutex<u64>,
        log: &Mutex<Vec<u64>>,
        applied: &[AtomicBool; 3],
        fail_on: u64,
    ) -> Result<u64, Stop<()>> {
        let seq = {
            let mut last = sequencer.lock().unwrap();
            *last += 1;
            t.queue(*last, *last);
            *last
        };
        t.make_durable(seq, |batch| {
            if batch.iter().any(|(s, _)| *s == fail_on) {
                return Err(());
            }
            log.lock().unwrap().extend(batch.iter().map(|(s, _)| *s));
            Ok(())
        })?;
        t.complete(seq, || {
            // Durable before applied, and applied in order.
            assert!(log.lock().unwrap().contains(&seq));
            for earlier in 1..seq {
                assert!(applied[earlier as usize].load(Ordering::Relaxed));
            }
            applied[seq as usize].store(true, Ordering::Relaxed);
            Ok(())
        })?;
        Ok(seq)
    }

    #[test]
    fn loom_commits_apply_in_order_and_visible_follows_apply() {
        loom::model(|| {
            let t = Arc::new(Turnstile::<u64>::new());
            let sequencer = Arc::new(Mutex::new(0));
            let log = Arc::new(Mutex::new(Vec::new()));
            let applied = Arc::new([
                AtomicBool::new(false),
                AtomicBool::new(false),
                AtomicBool::new(false),
            ]);
            let committers: Vec<_> = (0..2)
                .map(|_| {
                    let (t, sequencer, log, applied) = (
                        Arc::clone(&t),
                        Arc::clone(&sequencer),
                        Arc::clone(&log),
                        Arc::clone(&applied),
                    );
                    loom::thread::spawn(move || {
                        commit(&t, &sequencer, &log, &applied, u64::MAX).is_ok()
                    })
                })
                .collect();
            // A reader that sees a sequence number sees its apply.
            let seen = t.visible();
            for seq in 1..=seen {
                assert!(applied[seq as usize].load(Ordering::Relaxed));
            }
            for c in committers {
                assert!(c.join().unwrap());
            }
            assert_eq!(*log.lock().unwrap(), [1, 2]);
            assert_eq!(t.visible(), 2);
        });
    }

    #[test]
    fn loom_a_failed_write_stops_every_commit() {
        loom::model(|| {
            let t = Arc::new(Turnstile::<u64>::new());
            let sequencer = Arc::new(Mutex::new(0));
            let log = Arc::new(Mutex::new(Vec::new()));
            let applied = Arc::new([
                AtomicBool::new(false),
                AtomicBool::new(false),
                AtomicBool::new(false),
            ]);
            let committers: Vec<_> = (0..2)
                .map(|_| {
                    let (t, sequencer, log, applied) = (
                        Arc::clone(&t),
                        Arc::clone(&sequencer),
                        Arc::clone(&log),
                        Arc::clone(&applied),
                    );
                    loom::thread::spawn(move || commit(&t, &sequencer, &log, &applied, 1).is_ok())
                })
                .collect();
            for c in committers {
                // Commit 1 never writes, so neither commit applies.
                assert!(!c.join().unwrap());
            }
            assert!(t.halted());
            assert_eq!(t.visible(), 0);
            assert!(!applied[1].load(Ordering::Relaxed));
            assert!(!applied[2].load(Ordering::Relaxed));
        });
    }
}
