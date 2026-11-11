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

use std::{
    collections::HashMap,
    io::{BufReader, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{
        Arc, Condvar, Mutex, MutexGuard, PoisonError, TryLockError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use super::wire::{self, ERR, OK, REPLY, RESPONSE_HEAD};
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
/// Buffer for reading replies: a frame and its length usually arrive in one
/// read.
const READ_BUFFER: usize = 64 * 1024;
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
pub(crate) struct Reply {
    pub(crate) status: u8,
    frame: Vec<u8>,
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
#[derive(Default)]
struct Wait {
    reply: Option<std::result::Result<Reply, ()>>,
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
    fn new(limit: Duration) -> Slot {
        Slot {
            wait: Mutex::new(Wait::default()),
            ready: Condvar::new(),
            deadline: Instant::now() + limit,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Wait> {
        self.wait.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn fill(&self, reply: std::result::Result<Reply, ()>) {
        self.lock().reply = Some(reply);
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
    output: Mutex<BufReader<ChildStdout>>,
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

    /// Read replies until the one for `id` arrives, handing each other
    /// reply to its request. The stream ending, failing, or holding a frame
    /// that does not parse or that no request is waiting for ends the
    /// channel.
    fn read_until(&self, output: &mut BufReader<ChildStdout>, id: u64) -> Option<Reply> {
        while let Ok(Some(frame)) = wire::read_frame(output, RESPONSE_HEAD) {
            let mut r = Reader::new(&frame, REPLY, 0);
            let (Ok(got), Ok(status)) = (r.u64(), r.u8()) else {
                break;
            };
            if status != OK && status != ERR {
                break;
            }
            let Some(slot) = self.pending().remove(&got) else {
                break;
            };
            let reply = Reply { status, frame };
            if got == id {
                return Some(reply);
            }
            slot.fill(Ok(reply));
        }
        self.fail();
        None
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
            output: Mutex::new(BufReader::with_capacity(READ_BUFFER, output)),
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
        self.exchange(
            op,
            f,
            REQUEST_WAIT,
            "it did not answer in two minutes, and was ended",
        )
    }

    fn exchange(
        &self,
        op: u16,
        f: impl FnOnce(&mut Writer<'_>) -> Result<()>,
        limit: Duration,
        late: &'static str,
    ) -> Result<Reply> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let frame = wire::frame(
            |w| {
                w.u64(id);
                w.u16(op);
            },
            f,
        )?;
        let slot = Arc::new(Slot::new(limit));
        {
            let mut pending = self.shared.pending();
            if self.shared.dead.load(Ordering::Acquire) {
                return Err(gone());
            }
            let _ = pending.insert(id, Arc::clone(&slot));
        }
        self.write(&frame);
        loop {
            let output = match self.shared.output.try_lock() {
                Ok(output) => Some(output),
                Err(TryLockError::Poisoned(output)) => Some(output.into_inner()),
                Err(TryLockError::WouldBlock) => None,
            };
            if let Some(mut output) = output {
                // The read side is free. The request that held it may have
                // read this reply already; if not, read until it comes.
                let ready = slot.lock().reply.take();
                let reply = match ready {
                    Some(reply) => reply.ok(),
                    None => self.shared.read_until(&mut output, id),
                };
                drop(output);
                self.shared.pass_lead();
                return reply.ok_or_else(gone);
            }
            // Another request reads: wait for the reply, or for the turn to
            // read.
            let mut wait = slot.lock();
            loop {
                if let Some(reply) = wait.reply.take() {
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
        match wire::frame(
            |w| {
                w.u64(0);
                w.u16(op);
            },
            f,
        ) {
            Ok(frame) => self.write(&frame),
            Err(_) => self.shared.fail(),
        }
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
