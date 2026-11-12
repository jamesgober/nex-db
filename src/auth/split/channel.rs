//! The application's end of the channel to the auth process.
//!
//! Many threads share one channel. A request takes the writer lock only to
//! write its frame. Then it reads its own reply: the request that holds the
//! read side reads frames off the pipe, hands each other request its reply,
//! and returns with its own; a request that finds the read side taken waits
//! for its reply or for its turn to read. A lone request so takes one
//! wake-up for its reply, the pipe's, not two (the pipe's and then a reader
//! thread's).
//!
//! A watchdog thread checks every [`WATCH`] that the auth process is still
//! running and that no request has waited past its limit: the request that
//! reads is blocked on the pipe and cannot time itself out, so the watchdog
//! ends the process, which ends the pipe. When the auth process ends, or
//! sends a frame that does not parse, the channel is dead: every waiting
//! request and every later one fails with [`Error::Storage`], and
//! [`Channel::failure`] reports it to the core, which stops writes.
//!
//! A request allocates nothing once its thread has made one: the request
//! frame's buffer, the slot it waits in, and the reply's buffer are kept
//! per thread and reused. Every frame buffer is wiped once its frame is
//! sent or its reply dropped, and replies are read straight off the pipe
//! into a buffer that wipes each frame once handled, so passwords, tokens,
//! and secrets do not linger in this process's memory.

use std::{
    cell::RefCell,
    collections::HashMap,
    io::Write,
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{
        Arc, Condvar, Mutex, MutexGuard, PoisonError, TryLockError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use super::wire::{self, ERR, FRAME_BUFFER, FrameReader, OK, REPLY, RESPONSE_HEAD};
use crate::{
    core::codec::{Reader, Writer},
    error::{Error, Result},
};

/// How long the auth process has to answer the hello: a program whose
/// `main` does not call `serve_auth_process` never does.
const HELLO_WAIT: Duration = Duration::from_secs(30);

/// How long a closing database waits for the auth process to end before it
/// is killed.
const EXIT_WAIT: Duration = Duration::from_secs(30);
/// The longest any request waits for its reply. An auth process that does
/// not answer in time is ended, so the channel fails closed (every auth call
/// errors and writes stop) instead of leaving callers waiting.
const REQUEST_WAIT: Duration = Duration::from_secs(120);
/// The limit for a checkpoint or a backup, which write or copy a whole auth
/// store: long enough for a large one on a slow disk, short enough that an
/// auth process that hangs is still ended.
const LONG_WAIT: Duration = Duration::from_secs(60 * 60);

/// How long a request with `op` may wait, and what its error says past it.
/// Before 0.8 a checkpoint or backup had two minutes like any request, and
/// past them the auth process was ended and writes stopped.
fn limit(op: u16) -> (Duration, &'static str) {
    if matches!(op, super::op::CHECKPOINT | super::op::BACKUP) {
        (
            LONG_WAIT,
            "it did not finish a checkpoint or backup in an hour, and was ended",
        )
    } else {
        (
            REQUEST_WAIT,
            "it did not answer in two minutes, and was ended",
        )
    }
}
/// How often the watchdog checks the auth process and the waiting requests.
/// An auth process that ends while no request is waiting stops writes
/// within this time; one that ends during a request fails it at once.
const WATCH: Duration = Duration::from_millis(100);

fn gone() -> Error {
    Error::storage(
        "reaching the auth process",
        "the auth process ended or sent a malformed message",
    )
}

/// A response: its status and its frame, the payload after the header.
/// The frame's buffer is wiped when the reply is dropped, and kept for
/// this thread's next request.
pub(crate) struct Reply {
    pub(crate) status: u8,
    frame: Vec<u8>,
}

impl Drop for Reply {
    fn drop(&mut self) {
        wire::wipe_frame(&mut self.frame);
        let frame = std::mem::take(&mut self.frame);
        let _ = spare(move |spare| {
            if spare.reply.capacity() == 0 {
                spare.reply = frame;
            }
        });
    }
}

/// What a thread keeps between its requests: the request frame's buffer,
/// the slot it waits in, and the reply's buffer. Each is empty and wiped
/// while kept.
struct Spare {
    frame: Vec<u8>,
    slot: Option<Arc<Slot>>,
    reply: Vec<u8>,
}

thread_local! {
    static SPARE: RefCell<Spare> = const {
        RefCell::new(Spare {
            frame: Vec::new(),
            slot: None,
            reply: Vec::new(),
        })
    };
}

/// Run `f` on this thread's [`Spare`]; `None` while the thread ends.
fn spare<T>(f: impl FnOnce(&mut Spare) -> T) -> Option<T> {
    SPARE
        .try_with(|spare| spare.try_borrow_mut().ok().map(|mut spare| f(&mut spare)))
        .ok()
        .flatten()
}

impl Reply {
    pub(crate) fn body(&self) -> &[u8] {
        &self.frame[RESPONSE_HEAD..]
    }

    /// The result `read` decodes from an `OK` reply, or the error an `ERR`
    /// reply carries.
    pub(crate) fn decode<T>(&self, read: impl FnOnce(&mut Reader<'_>) -> Result<T>) -> Result<T> {
        let mut r = Reader::new(self.body(), REPLY, 0);
        match self.status {
            OK => read(&mut r)
                .and_then(|value| r.finish().map(|()| value))
                .map_err(wire::malformed),
            _ => Err(wire::get_error(&mut r)),
        }
    }
}

/// What a waiting request is woken for: its reply, once read, or its turn
/// to take the read side.
struct Wait {
    /// The reply's status once read, with its frame in `frame`; `Err`
    /// when the channel ended first.
    reply: Option<std::result::Result<u8, ()>>,
    /// The buffer the reply's frame is copied into.
    frame: Vec<u8>,
    lead: bool,
}

/// One request in flight.
struct Slot {
    wait: Mutex<Wait>,
    ready: Condvar,
    /// When the request stops waiting. Past it the auth process is ended:
    /// by the request itself when it waits, by the watchdog when it reads.
    deadline: Instant,
}

impl Slot {
    /// A slot for a request that may wait `limit`: this thread's kept one,
    /// or a new one.
    fn take(limit: Duration) -> Arc<Slot> {
        let deadline = Instant::now() + limit;
        let buffer = || {
            spare(|spare| std::mem::take(&mut spare.reply))
                .filter(|reply| reply.capacity() > 0)
                .unwrap_or_else(|| Vec::with_capacity(FRAME_BUFFER))
        };
        if let Some(mut slot) = spare(|spare| spare.slot.take()).flatten() {
            if let Some(kept) = Arc::get_mut(&mut slot) {
                kept.deadline = deadline;
                let wait = kept.wait.get_mut().unwrap_or_else(PoisonError::into_inner);
                wait.reply = None;
                wait.lead = false;
                if wait.frame.capacity() == 0 {
                    wait.frame = buffer();
                }
                return slot;
            }
        }
        Arc::new(Slot {
            wait: Mutex::new(Wait {
                reply: None,
                frame: buffer(),
                lead: false,
            }),
            ready: Condvar::new(),
            deadline,
        })
    }

    /// Keep `slot` for this thread's next request, when nothing else holds
    /// it (none can take it again: it left the pending map).
    fn keep(slot: Arc<Slot>) {
        if Arc::strong_count(&slot) == 1 {
            let _ = spare(move |spare| spare.slot = Some(slot));
        }
    }

    fn lock(&self) -> MutexGuard<'_, Wait> {
        self.wait.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The reply, once there is one.
    fn reply(wait: &mut Wait) -> Option<std::result::Result<Reply, ()>> {
        let status = wait.reply.take()?;
        Some(status.map(|status| Reply {
            status,
            frame: std::mem::take(&mut wait.frame),
        }))
    }

    /// Hand the request its reply (status and frame), or `Err` when the
    /// channel ended.
    fn fill(&self, reply: std::result::Result<(u8, &[u8]), ()>) {
        {
            let mut guard = self.lock();
            let wait = &mut *guard;
            wait.reply = Some(reply.map(|(status, frame)| {
                // The buffer is empty and wiped: growing it leaves nothing.
                wait.frame.clear();
                wait.frame.extend_from_slice(frame);
                status
            }));
        }
        self.ready.notify_one();
    }

    fn lead(&self) {
        self.lock().lead = true;
        self.ready.notify_one();
    }
}

/// What the requests and the watchdog share.
struct Shared {
    pending: Mutex<HashMap<u64, Arc<Slot>>>,
    dead: AtomicBool,
    /// The read side of the pipe: the request that holds it reads.
    output: Mutex<FrameReader<ChildStdout>>,
    child: Mutex<Option<Child>>,
    /// Set when the channel closes, to end the watchdog.
    closing: AtomicBool,
}

impl Shared {
    fn pending(&self) -> MutexGuard<'_, HashMap<u64, Arc<Slot>>> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Mark the channel dead and fail every waiting request. A request
    /// checks `dead` under the same lock before it waits, so none is left
    /// waiting.
    fn fail(&self) {
        let mut pending = self.pending();
        self.dead.store(true, Ordering::Release);
        for (_, slot) in pending.drain() {
            slot.fill(Err(()));
        }
    }

    /// End the auth process now and fail every request.
    fn kill(&self) {
        if let Some(child) = self
            .child
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
        {
            let _ = child.kill();
        }
        self.fail();
    }

    /// Read replies until the one for `id` arrives, handing each reply to
    /// its request's slot; `false` when the channel ended first. The stream
    /// ending, failing, or holding a frame that does not parse or that no
    /// request is waiting for ends the channel.
    fn read_until(&self, output: &mut FrameReader<ChildStdout>, id: u64) -> bool {
        loop {
            let step = output.next(RESPONSE_HEAD, |frame| {
                let mut r = Reader::new(frame, REPLY, 0);
                let (Ok(got), Ok(status)) = (r.u64(), r.u8()) else {
                    return None;
                };
                if status != OK && status != ERR {
                    return None;
                }
                let slot = self.pending().remove(&got)?;
                slot.fill(Ok((status, frame)));
                Some(got == id)
            });
            match step {
                Ok(Some(Some(true))) => return true,
                Ok(Some(Some(false))) => {}
                _ => break,
            }
        }
        self.fail();
        false
    }

    /// Give the read side's turn to one waiting request, if any. Called by
    /// a request after it let go of the read side.
    fn pass_lead(&self) {
        if let Some(slot) = self.pending().values().next() {
            slot.lead();
        }
    }

    /// The watchdog: until the channel closes, every [`WATCH`], end the
    /// channel if the auth process has exited, and end the auth process if
    /// a request has waited past its limit.
    fn watch(&self) {
        while !self.closing.load(Ordering::Acquire) {
            std::thread::park_timeout(WATCH);
            if self.dead.load(Ordering::Acquire) {
                continue;
            }
            let exited = self
                .child
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_mut()
                .is_some_and(|child| !matches!(child.try_wait(), Ok(None)));
            if exited {
                self.fail();
                continue;
            }
            let now = Instant::now();
            let late = self.pending().values().any(|slot| slot.deadline <= now);
            if late {
                self.kill();
            }
        }
    }
}

/// The channel to one auth process.
pub(crate) struct Channel {
    shared: Arc<Shared>,
    input: Mutex<Option<ChildStdin>>,
    next: AtomicU64,
    watchdog: Mutex<Option<JoinHandle<()>>>,
    pid: u32,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("pid", &self.pid)
            .field("dead", &self.shared.dead.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Channel {
    /// Start the auth process from `program` (the running program when
    /// `None`) and send it the hello `hello` writes.
    pub(crate) fn start(
        program: Option<&Path>,
        hello: impl FnOnce(&mut Writer<'_>) -> Result<()>,
    ) -> Result<Arc<Channel>> {
        let program = match program {
            Some(program) => program.to_path_buf(),
            None => std::env::current_exe()
                .map_err(|e| Error::storage("finding the program to start the auth process", e))?,
        };
        let mut child = Command::new(&program)
            .env(super::ENV, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| Error::storage("starting the auth process", e))?;
        let pid = child.id();
        let (Some(input), Some(output)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::storage(
                "starting the auth process",
                "its pipes are missing",
            ));
        };
        let shared = Arc::new(Shared {
            pending: Mutex::new(HashMap::new()),
            dead: AtomicBool::new(false),
            output: Mutex::new(FrameReader::new(output)),
            child: Mutex::new(Some(child)),
            closing: AtomicBool::new(false),
        });
        let watched = Arc::clone(&shared);
        let watchdog = std::thread::Builder::new()
            .name("nex-db-auth-watchdog".to_owned())
            .spawn(move || watched.watch());
        let watchdog = match watchdog {
            Ok(watchdog) => watchdog,
            Err(e) => {
                shared.kill();
                let child = shared
                    .child
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take();
                if let Some(mut child) = child {
                    let _ = child.wait();
                }
                return Err(Error::storage("starting the auth channel", e));
            }
        };
        let channel = Arc::new(Channel {
            shared,
            input: Mutex::new(Some(input)),
            next: AtomicU64::new(1),
            watchdog: Mutex::new(Some(watchdog)),
            pid,
        });
        let reply = channel.exchange(
            super::op::HELLO,
            hello,
            HELLO_WAIT,
            "it did not answer the hello: does the program's main call nex_db::serve_auth_process first?",
        )?;
        reply.decode(|r| {
            if r.fixed::<8>()? != *HELLO_REPLY {
                return Err(Error::corrupt(REPLY, 0));
            }
            Ok(())
        })?;
        Ok(channel)
    }

    /// The auth process's id.
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    /// The error the core stops writes with, once the channel is dead.
    pub(crate) fn failure(&self) -> Option<Error> {
        self.shared.dead.load(Ordering::Acquire).then(gone)
    }

    /// Send a request whose payload `f` writes and wait for its reply.
    pub(crate) fn request(
        &self,
        op: u16,
        f: impl FnOnce(&mut Writer<'_>) -> Result<()>,
    ) -> Result<Reply> {
        let (limit, late) = limit(op);
        self.exchange(op, f, limit, late)
    }

    fn exchange(
        &self,
        op: u16,
        f: impl FnOnce(&mut Writer<'_>) -> Result<()>,
        limit: Duration,
        late: &'static str,
    ) -> Result<Reply> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let mut frame = spare(|spare| std::mem::take(&mut spare.frame)).unwrap_or_default();
        let sent = wire::frame_into(
            &mut frame,
            |w| {
                w.u64(id);
                w.u16(op);
            },
            f,
        )
        .and_then(|()| {
            let slot = Slot::take(limit);
            {
                let mut pending = self.shared.pending();
                if self.shared.dead.load(Ordering::Acquire) {
                    return Err(gone());
                }
                let _ = pending.insert(id, Arc::clone(&slot));
            }
            self.write(&frame);
            Ok(slot)
        });
        wire::wipe_frame(&mut frame);
        let _ = spare(move |spare| spare.frame = frame);
        let slot = sent?;
        loop {
            let output = match self.shared.output.try_lock() {
                Ok(output) => Some(output),
                Err(TryLockError::Poisoned(output)) => Some(output.into_inner()),
                Err(TryLockError::WouldBlock) => None,
            };
            if let Some(mut output) = output {
                // The read side is free. The request that held it may have
                // read this reply already; if not, read until it comes.
                let mut ready = Slot::reply(&mut slot.lock());
                if ready.is_none() && self.shared.read_until(&mut output, id) {
                    ready = Slot::reply(&mut slot.lock());
                }
                drop(output);
                self.shared.pass_lead();
                Slot::keep(slot);
                return ready.and_then(std::result::Result::ok).ok_or_else(gone);
            }
            // Another request reads: wait for the reply, or for the turn to
            // read.
            let mut wait = slot.lock();
            loop {
                if let Some(reply) = Slot::reply(&mut wait) {
                    drop(wait);
                    Slot::keep(slot);
                    return reply.map_err(|()| gone());
                }
                if wait.lead {
                    wait.lead = false;
                    break;
                }
                let left = slot.deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    drop(wait);
                    self.shared.kill();
                    return Err(Error::storage("the auth process", late));
                }
                wait = slot
                    .ready
                    .wait_timeout(wait, left)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
        }
    }

    /// Send a message that gets no response. A failure kills the channel,
    /// which later calls report.
    pub(crate) fn send(&self, op: u16, f: impl FnOnce(&mut Writer<'_>) -> Result<()>) {
        if self.shared.dead.load(Ordering::Acquire) {
            return;
        }
        let mut frame = spare(|spare| std::mem::take(&mut spare.frame)).unwrap_or_default();
        let built = wire::frame_into(
            &mut frame,
            |w| {
                w.u64(0);
                w.u16(op);
            },
            f,
        );
        match built {
            Ok(()) => self.write(&frame),
            Err(_) => self.shared.fail(),
        }
        wire::wipe_frame(&mut frame);
        let _ = spare(move |spare| spare.frame = frame);
    }

    fn write(&self, frame: &[u8]) {
        let mut input = self.input.lock().unwrap_or_else(PoisonError::into_inner);
        let written = match input.as_mut() {
            Some(pipe) => pipe.write_all(frame).and_then(|()| pipe.flush()).is_ok(),
            None => false,
        };
        if !written {
            drop(input);
            self.shared.fail();
        }
    }
}

/// What the auth process answers the hello with.
pub(crate) const HELLO_REPLY: &[u8; 8] = b"NXDBAUTH";

impl Drop for Channel {
    fn drop(&mut self) {
        // Closing its input ends the auth process: it finishes the requests
        // it holds and exits.
        drop(
            self.input
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(),
        );
        let child = self
            .shared
            .child
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(mut child) = child {
            let started = Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if started.elapsed() < EXIT_WAIT => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    _ => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                }
            }
        }
        self.shared.closing.store(true, Ordering::Release);
        if let Some(watchdog) = self
            .watchdog
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            watchdog.thread().unpark();
            let _ = watchdog.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoints_and_backups_have_their_own_limit() {
        use super::super::op;
        assert_eq!(limit(op::VALIDATE).0, REQUEST_WAIT);
        assert_eq!(limit(op::CHECKPOINT).0, LONG_WAIT);
        assert_eq!(limit(op::BACKUP).0, LONG_WAIT);
        assert!(LONG_WAIT > REQUEST_WAIT * 10);
    }
}
