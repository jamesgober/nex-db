//! Scheduled publishing: the schedule index and the thread that fires it.
//!
//! Each locale of an entity can hold one schedule (publish or unpublish at a
//! time), kept in its head. The index orders every schedule by time; it is
//! rebuilt from the heads at open and updated as commits apply. One thread
//! per open database sleeps until the earliest schedule is due (or a commit
//! changes the earliest), then fires each due schedule in its own commit.

use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Condvar, Mutex, PoisonError},
    thread::JoinHandle,
    time::Duration,
};

use super::{entity::Action, entity::Head, locale::Locale};
use crate::{
    Database,
    core::now_ms,
    db::Inner,
    error::{Error, Result},
    ids::Rid,
};

/// Longest the thread sleeps without a look at the clock: a clock that
/// steps, or a schedule this misses, waits at most this long.
const MAX_SLEEP: Duration = Duration::from_secs(30);
/// Pause after a schedule could not fire, so a failing one does not spin.
const BACKOFF: Duration = Duration::from_secs(1);

/// One schedule as the index orders it: time, entity, locale, action.
type Row = (u64, Rid, Locale, Action);

#[derive(Debug, Default)]
struct Index {
    rows: BTreeSet<Row>,
    placed: HashMap<Rid, Vec<Row>>,
}

/// Every schedule, earliest first.
#[derive(Debug, Default)]
pub(crate) struct Schedules {
    inner: Mutex<Index>,
    wake: Arc<Wake>,
}

impl Schedules {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Index> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Place `head`'s schedules as they now are; wake the thread when the
    /// earliest one changed.
    pub(crate) fn update(&self, head: &Head) {
        let rows: Vec<Row> = head
            .variants
            .iter()
            .filter_map(|v| v.schedule.map(|(a, at)| (at, head.rid, v.locale, a)))
            .collect();
        let earlier = {
            let mut inner = self.lock();
            let first = inner.rows.first().copied();
            for row in inner.placed.remove(&head.rid).unwrap_or_default() {
                let _ = inner.rows.remove(&row);
            }
            for row in &rows {
                let _ = inner.rows.insert(*row);
            }
            if !rows.is_empty() {
                let _ = inner.placed.insert(head.rid, rows);
            }
            inner.rows.first().copied() != first
        };
        if earlier {
            self.wake.notify();
        }
    }

    /// Forget `rid`'s schedules: it was deleted.
    pub(crate) fn remove(&self, rid: Rid) {
        let mut inner = self.lock();
        for row in inner.placed.remove(&rid).unwrap_or_default() {
            let _ = inner.rows.remove(&row);
        }
    }

    /// When the earliest schedule is due, if there is one.
    fn next(&self) -> Option<u64> {
        self.lock().rows.first().map(|r| r.0)
    }

    /// Every schedule due at `now`, earliest first.
    pub(crate) fn due(&self, now: u64) -> Vec<(u64, Rid, Locale, Action)> {
        self.lock()
            .rows
            .iter()
            .take_while(|r| r.0 <= now)
            .copied()
            .collect()
    }
}

/// Wakes the scheduling thread: a commit changed the earliest schedule, or
/// the database is closing.
#[derive(Debug, Default)]
struct Wake {
    /// (woken, stopping).
    state: Mutex<(bool, bool)>,
    signal: Condvar,
}

impl Wake {
    fn notify(&self) {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).0 = true;
        self.signal.notify_all();
    }

    fn stop(&self) {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).1 = true;
        self.signal.notify_all();
    }

    /// Sleep up to `limit` or until woken; false once stopping.
    fn sleep(&self, limit: Duration) -> bool {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if !state.0 && !state.1 {
            state = self
                .signal
                .wait_timeout(state, limit)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        state.0 = false;
        !state.1
    }
}

/// The scheduling thread of one open database.
#[derive(Debug)]
pub(crate) struct Scheduler {
    wake: Arc<Wake>,
    thread: Option<JoinHandle<()>>,
}

impl Scheduler {
    /// Start the thread for the database `inner` belongs to.
    pub(crate) fn start(inner: Arc<Inner>) -> Result<Scheduler> {
        let wake = Arc::clone(&inner.content_engine().schedules.wake);
        let thread_wake = Arc::clone(&wake);
        let thread = std::thread::Builder::new()
            .name("nex-db-schedule".to_owned())
            .spawn(move || run(&Database::handle(inner), &thread_wake))
            .map_err(|e| Error::storage("starting the scheduling thread", e))?;
        Ok(Scheduler {
            wake,
            thread: Some(thread),
        })
    }

    /// Stop the thread and wait for it.
    pub(crate) fn stop(mut self) {
        self.wake.stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run(db: &Database, wake: &Wake) {
    let schedules = &db.content_engine().schedules;
    loop {
        let now = now_ms();
        let sleep = match schedules.next() {
            Some(at) if at <= now => {
                if db.content().fire_due(now) {
                    continue;
                }
                BACKOFF
            }
            Some(at) => Duration::from_millis(at - now).min(MAX_SLEEP),
            None => MAX_SLEEP,
        };
        if !wake.sleep(sleep) {
            return;
        }
    }
}
