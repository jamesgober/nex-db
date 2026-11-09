//! The application's end of the channel to the auth process.
//!
//! Many threads share one channel. A request takes the writer lock only to
//! write its frame; one reader thread hands each response to the request
//! with its id. When the auth process ends, or sends a frame that does not
//! parse, the channel is dead: every waiting request and every later one
//! fails with [`Error::Storage`], and [`Channel::failure`] reports it to the
//! core, which stops writes.

use std::{
    collections::HashMap,
    io::{BufReader, Write},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc, Condvar, Mutex, PoisonError,
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
/// How long a request watches for its reply before it sleeps on it. Most
/// replies come within this, and a thread that is still running sees one
/// sooner than one that has to be woken.
const SPIN_WAIT: Duration = Duration::from_micros(50);
/// Buffer for reading replies: a frame and its length usually arrive in one
/// read.
const READ_BUFFER: usize = 64 * 1024;

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

#[derive(Default)]
struct Slot {
    reply: Mutex<Option<std::result::Result<Reply, ()>>>,
    ready: Condvar,
    /// Set after the reply is in place, for a request still spinning.
    filled: AtomicBool,
}

impl Slot {
    fn fill(&self, reply: std::result::Result<Reply, ()>) {
        *self.reply.lock().unwrap_or_else(PoisonError::into_inner) = Some(reply);
        self.filled.store(true, Ordering::Release);
        self.ready.notify_one();
    }

    /// Watch for the reply for up to [`SPIN_WAIT`]; true when it came.
    fn spin(&self) -> bool {
        let started = Instant::now();
        loop {
            for _ in 0..64 {
                if self.filled.load(Ordering::Acquire) {
                    return true;
                }
                std::hint::spin_loop();
            }
            if started.elapsed() >= SPIN_WAIT {
                return false;
            }
        }
    }
}

/// What the reader thread shares with the requests.
#[derive(Default)]
struct Shared {
    pending: Mutex<HashMap<u64, Arc<Slot>>>,
    dead: AtomicBool,
}

impl Shared {
    /// Mark the channel dead and fail every waiting request. A request
    /// checks `dead` under the same lock before it waits, so none is left
    /// waiting.
    fn fail(&self) {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        self.dead.store(true, Ordering::Release);
        for (_, slot) in pending.drain() {
            slot.fill(Err(()));
        }
    }
}

/// The channel to one auth process.
pub(crate) struct Channel {
    shared: Arc<Shared>,
    input: Mutex<Option<ChildStdin>>,
    next: AtomicU64,
    child: Mutex<Option<Child>>,
    reader: Mutex<Option<JoinHandle<()>>>,
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
        let shared = Arc::new(Shared::default());
        let reader_shared = Arc::clone(&shared);
        let reader = std::thread::Builder::new()
            .name("nex-db-auth-channel".to_owned())
            .spawn(move || {
                let shared = reader_shared;
                let mut output = BufReader::with_capacity(READ_BUFFER, output);
                // The stream ending, failing, or holding a frame that does
                // not parse ends the channel.
                while let Ok(Some(frame)) = wire::read_frame(&mut output, RESPONSE_HEAD) {
                    let mut r = Reader::new(&frame, REPLY, 0);
                    let (Ok(id), Ok(status)) = (r.u64(), r.u8()) else {
                        break;
                    };
                    if status != OK && status != ERR {
                        break;
                    }
                    let slot = shared
                        .pending
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .remove(&id);
                    match slot {
                        Some(slot) => slot.fill(Ok(Reply { status, frame })),
                        // A response nobody asked for: the stream is not
                        // what this side wrote for.
                        None => break,
                    }
                }
                shared.fail();
            });
        let reader = match reader {
            Ok(reader) => reader,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::storage("starting the auth channel", e));
            }
        };
        let channel = Arc::new(Channel {
            shared,
            input: Mutex::new(Some(input)),
            next: AtomicU64::new(1),
            child: Mutex::new(Some(child)),
            reader: Mutex::new(Some(reader)),
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
        let slot = Arc::new(Slot::default());
        {
            let mut pending = self
                .shared
                .pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if self.shared.dead.load(Ordering::Acquire) {
                return Err(gone());
            }
            let _ = pending.insert(id, Arc::clone(&slot));
        }
        self.write(&frame);
        let _ = slot.spin();
        let mut reply = slot.reply.lock().unwrap_or_else(PoisonError::into_inner);
        let started = Instant::now();
        loop {
            if let Some(reply) = reply.take() {
                return reply.map_err(|()| gone());
            }
            let left = limit.saturating_sub(started.elapsed());
            if left.is_zero() {
                drop(reply);
                self.kill();
                return Err(Error::storage("the auth process", late));
            }
            reply = slot
                .ready
                .wait_timeout(reply, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
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

    /// End the auth process now.
    fn kill(&self) {
        if let Some(child) = self
            .child
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
        {
            let _ = child.kill();
        }
        self.shared.fail();
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
        if let Some(mut child) = self
            .child
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
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
        if let Some(reader) = self
            .reader
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            let _ = reader.join();
        }
    }
}
