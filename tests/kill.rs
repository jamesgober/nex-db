//! Kill test: a child process commits in a loop and is killed at a random
//! point; the database is then reopened and checked against every commit the
//! child acknowledged.
//!
//! Each iteration the child opens the database, hashes one password, then
//! repeats one commit (an account, a profile page, and a session) and prints
//! `ACK <i> <token>` after `commit` returns. Every fourth commit is followed
//! by a revocation commit and `REVOKED <i>`. The parent kills the child
//! (`SIGKILL` / `TerminateProcess`), sometimes while it is still opening the
//! database, then reopens and checks:
//!
//! - the database opens;
//! - every acknowledged commit is there, whole: the session validates (or is
//!   revoked, when the revocation was acknowledged), the profile resolves and
//!   names the session's account;
//! - the commit in flight is either whole or absent: its profile exists
//!   exactly when its identifier is taken;
//! - nothing past it exists.
//!
//! The iteration count comes from `NEX_KILL_ITERATIONS` (default 25). The
//! 0.1.0 exit criterion is 10,000:
//!
//! ```text
//! NEX_KILL_ITERATIONS=10000 cargo test --release --test kill -- --nocapture
//! ```

use std::{
    collections::HashMap,
    env,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use nex_db::{Database, Entity, Error, HashedPassword, SessionSpec, Validation, Value};

const SITE: &str = "kill.example";

fn identifier(i: u64) -> String {
    format!("k{i}@example.com")
}

fn profile_path(i: u64) -> String {
    format!("/k/{i}")
}

/// The child: commit until killed.
#[test]
fn kill_child() {
    let (Ok(dir), Ok(start)) = (env::var("NEX_KILL_CHILD"), env::var("NEX_KILL_START")) else {
        return;
    };
    let start: u64 = start.parse().unwrap();
    // Half the children checkpoint (and truncate the log) every few
    // commits, so kills land inside checkpoints too.
    let mut builder = Database::builder(&dir);
    if let Some(every) = env::var("NEX_KILL_CHECKPOINT")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        builder = builder.checkpoint_every(every);
    }
    let db = builder.open().unwrap();
    let password = db.auth().hash_password("kill test password").unwrap();
    let mut out = std::io::stdout().lock();
    writeln!(out, "READY").unwrap();
    out.flush().unwrap();
    for i in start..start + 10_000 {
        let token = db
            .commit(|tx| {
                let account = tx.auth().create_account(&identifier(i), &password)?;
                let _ = tx.content().create(
                    Entity::new("profile")
                        .field("account", account)
                        .site(SITE)
                        .path(profile_path(i)),
                )?;
                tx.auth().issue_session(account, SessionSpec::web())
            })
            .unwrap();
        writeln!(out, "ACK {i} {}", token.as_str()).unwrap();
        out.flush().unwrap();
        if i % 4 == 3 {
            assert!(db.auth().revoke(&token).unwrap());
            writeln!(out, "REVOKED {i}").unwrap();
            out.flush().unwrap();
        }
    }
}

/// A small xorshift generator; the seed is printed so a failure can be
/// replayed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// What the parent knows about one commit.
struct Known {
    /// The token, when the commit was acknowledged.
    token: Option<String>,
    /// The revocation was acknowledged.
    revoked: bool,
}

/// Exists exactly when `identifier` is taken: stage an account for it and
/// abort the commit.
fn identifier_taken(db: &Database, password: &HashedPassword, identifier: &str) -> bool {
    let probe: nex_db::Result<()> = db.commit(|tx| {
        let _ = tx.auth().create_account(identifier, password)?;
        Err(Error::Invalid {
            field: "probe",
            reason: "abort",
        })
    });
    match probe {
        Err(Error::AlreadyExists { .. }) => true,
        Err(Error::Invalid { field: "probe", .. }) => false,
        other => panic!("probe for {identifier}: {other:?}"),
    }
}

fn check_commit(db: &Database, i: u64, known: &Known) {
    let token = known.token.as_deref().unwrap();
    let check = db.auth().validate(token).unwrap();
    let session = match check {
        Validation::Valid(session) => {
            assert!(!known.revoked, "commit {i}: revoked session validates");
            Some(session)
        }
        Validation::Revoked { .. } => None,
        other => panic!("commit {i}: acknowledged session is {other:?}"),
    };
    let route = db
        .content()
        .resolve(SITE, &profile_path(i))
        .unwrap()
        .unwrap_or_else(|| panic!("commit {i}: acknowledged profile missing"));
    let entry = db.content().get(route.entity()).unwrap().unwrap();
    if let Some(session) = session {
        assert_eq!(
            entry.field("account").and_then(Value::as_account),
            Some(session.account()),
            "commit {i}: profile and session disagree"
        );
    }
}

fn run_child(dir: &Path, start: u64, rng: &mut Rng) -> Vec<String> {
    let mut command = Command::new(env::current_exe().unwrap());
    if rng.below(2) == 0 {
        let _ = command.env("NEX_KILL_CHECKPOINT", (1 + rng.below(4096)).to_string());
    }
    let mut child = command
        .args(["kill_child", "--exact", "--nocapture", "--test-threads=1"])
        .env("NEX_KILL_CHILD", dir)
        .env("NEX_KILL_START", start.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let reader = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let mut lines = Vec::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                // A line cut by the kill has no newline: not acknowledged.
                Ok(_) if line.ends_with('\n') => {
                    let text = line.trim_end().to_owned();
                    // The test harness prints its "test kill_child ... "
                    // prefix on the same line.
                    if text.ends_with("READY") {
                        let _ = tx.send(text.clone());
                    }
                    lines.push(text);
                }
                Ok(_) => {}
            }
        }
        lines
    });

    // One kill in five lands while the child may still be opening (and
    // recovering) the database; the rest land while it commits.
    let during_open = rng.below(5) == 0;
    if during_open {
        thread::sleep(Duration::from_millis(rng.below(60)));
    } else {
        let _ = rx.recv_timeout(Duration::from_secs(30));
        thread::sleep(Duration::from_micros(rng.below(40_000)));
    }
    let _ = child.kill();
    let _ = child.wait();
    reader.join().unwrap()
}

#[test]
fn kill_test() {
    if env::var("NEX_KILL_CHILD").is_ok() {
        return;
    }
    let iterations: u64 = env::var("NEX_KILL_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(25);
    let seed = env::var("NEX_KILL_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
                | 1
        });
    let dir: PathBuf = env::temp_dir().join(format!("nex-db-kill-{}-{seed}", std::process::id()));
    eprintln!(
        "kill test: {iterations} iterations, seed {seed}, dir {}",
        dir.display()
    );

    let password = {
        let db = Database::open(&dir).unwrap();
        db.auth().hash_password("kill test password").unwrap()
    };
    let mut rng = Rng(seed);
    let mut known: HashMap<u64, Known> = HashMap::new();
    // Commits 0..next are in the database.
    let mut next: u64 = 0;
    let started = Instant::now();

    for iteration in 0..iterations {
        let lines = run_child(&dir, next, &mut rng);
        let mut last_ack = None;
        for line in &lines {
            let mut parts = line.split(' ');
            match (parts.next(), parts.next(), parts.next()) {
                (Some("ACK"), Some(i), Some(token)) => {
                    let i: u64 = i.parse().unwrap();
                    let _ = known.insert(
                        i,
                        Known {
                            token: Some(token.to_owned()),
                            revoked: false,
                        },
                    );
                    last_ack = Some(i);
                }
                (Some("REVOKED"), Some(i), None) => {
                    let i: u64 = i.parse().unwrap();
                    known.get_mut(&i).unwrap().revoked = true;
                }
                _ => {}
            }
        }

        let db = Database::open(&dir)
            .unwrap_or_else(|e| panic!("iteration {iteration} (seed {seed}): reopen failed: {e}"));
        if let Some(last) = last_ack {
            next = last + 1;
        }
        // Every acknowledged commit of this child, and a sample of older
        // ones (all of them every 100 iterations).
        let full = iteration % 100 == 99;
        for (&i, commit) in &known {
            let recent = last_ack.is_some_and(|last| i + 8 > last);
            if commit.token.is_some() && (full || recent) {
                check_commit(&db, i, commit);
            }
        }
        // The commit in flight is whole or absent.
        let in_flight_profile = db
            .content()
            .resolve(SITE, &profile_path(next))
            .unwrap()
            .is_some();
        let in_flight_account = identifier_taken(&db, &password, &identifier(next));
        assert_eq!(
            in_flight_profile, in_flight_account,
            "iteration {iteration} (seed {seed}): commit {next} is in part"
        );
        if in_flight_profile {
            let _ = known.insert(
                next,
                Known {
                    token: None,
                    revoked: false,
                },
            );
            next += 1;
        }
        // Nothing past it.
        assert!(
            db.content()
                .resolve(SITE, &profile_path(next))
                .unwrap()
                .is_none(),
            "iteration {iteration} (seed {seed}): commit {next} appeared"
        );
        assert!(!identifier_taken(&db, &password, &identifier(next)));
        drop(db);
    }

    // A last full check.
    let db = Database::open(&dir).unwrap();
    for (&i, commit) in &known {
        if commit.token.is_some() {
            check_commit(&db, i, commit);
        }
    }
    drop(db);
    eprintln!(
        "kill test: {iterations} iterations, {next} commits, {:.1?}",
        started.elapsed()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
