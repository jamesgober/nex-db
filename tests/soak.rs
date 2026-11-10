//! A soak test: a mixed workload on every engine for a while, checking the
//! answers as it goes.
//!
//! Short by default so it runs on every CI platform. For a long run:
//!
//! ```text
//! NEX_SOAK_SECS=3600 cargo test --release --test soak -- --nocapture
//! ```
//!
//! Each round of the writer signs an account up, issues a session that
//! lives a second, publishes a page, edits and republishes it, revokes some
//! sessions, and every so often closes and opens the database. Readers
//! validate tokens and read pages the whole time. The checks: a revoked
//! token is never valid again, a published page only moves forward, every
//! call succeeds, and the database is healthy at the end.

use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use nex_db::{Database, Entity, Patch, SessionSpec, Validation, Value};

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn open(dir: &PathBuf) -> Database {
    Database::builder(dir).max_sessions(200_000).open().unwrap()
}

#[test]
fn test_soak() {
    let secs: u64 = std::env::var("NEX_SOAK_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    let dir = TempDir(std::env::temp_dir().join(format!(
        "nex-db-soak-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    // Readers take the database from here each round, so the writer can
    // close and open it while they run.
    let shared: Mutex<Option<Arc<Database>>> = Mutex::new(Some(Arc::new(open(&dir.0))));
    let current = || Arc::clone(shared.lock().unwrap().as_ref().unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let rounds = Arc::new(AtomicU64::new(0));
    // Tokens revoked so far, which must never validate again.
    let revoked: Arc<Mutex<Vec<String>>> = Arc::default();
    // Live tokens a reader may check.
    let live: Arc<Mutex<Vec<String>>> = Arc::default();
    let page = {
        let db = current();
        let rid = db
            .content()
            .create(Entity::new("page").field("n", 0_i64).path("/soak"))
            .unwrap();
        let _ = db.content().publish(rid).unwrap();
        rid
    };
    let hashed = current().auth().hash_password("soak password").unwrap();
    let deadline = Instant::now() + Duration::from_secs(secs);

    std::thread::scope(|s| {
        // Readers.
        for _ in 0..3 {
            let (stop, revoked, live) = (&stop, &revoked, &live);
            let current = &current;
            s.spawn(move || {
                let mut last_n = 0_i64;
                while !stop.load(Ordering::Relaxed) {
                    let db = current();
                    let token = live.lock().unwrap().last().cloned();
                    if let Some(token) = token {
                        // Valid, expired, or revoked: never an error.
                        let _ = db.auth().validate(&token).unwrap();
                    }
                    let gone = revoked.lock().unwrap().last().cloned();
                    if let Some(gone) = gone {
                        let v = db.auth().validate(&gone).unwrap();
                        assert!(
                            !matches!(v, Validation::Valid(_)),
                            "a revoked token was valid"
                        );
                    }
                    if let Some(entry) = db.content().get(page).unwrap() {
                        let n = entry.field("n").and_then(Value::as_int).unwrap();
                        assert!(n >= last_n, "page went back from {last_n} to {n}");
                        last_n = n;
                    }
                }
            });
        }
        // The writer.
        let mut n = 0_i64;
        while Instant::now() < deadline {
            let db = current();
            let round = rounds.fetch_add(1, Ordering::Relaxed);
            let account = db
                .auth()
                .create_account(&format!("soak{round}@example.com"), &hashed)
                .unwrap();
            let spec = SessionSpec::new(Duration::from_secs(1)).unwrap();
            let token = db.auth().issue_session(account, spec).unwrap();
            if round % 3 == 0 {
                assert!(db.auth().revoke(&token).unwrap());
                let mut revoked = revoked.lock().unwrap();
                revoked.push(token.as_str().to_owned());
                if revoked.len() > 1_000 {
                    let _ = revoked.drain(..500);
                }
            } else {
                let mut live = live.lock().unwrap();
                live.push(token.as_str().to_owned());
                if live.len() > 1_000 {
                    let _ = live.drain(..500);
                }
            }
            n += 1;
            db.content()
                .save_draft(page, Patch::new().set("n", n))
                .unwrap();
            let _ = db.content().publish(page).unwrap();
            let rid = db
                .content()
                .create(Entity::new("note").path(format!("/n/{round}")))
                .unwrap();
            let _ = db.content().publish(rid).unwrap();
            if round % 500 == 499 {
                // Close and open: recovery under the workload. Readers wait
                // on the slot meanwhile; the old database closes once the
                // last reader lets go of it.
                drop(db);
                let mut slot = shared.lock().unwrap();
                let old = slot.take().unwrap();
                while Arc::strong_count(&old) > 1 {
                    std::thread::sleep(Duration::from_millis(1));
                }
                drop(old);
                *slot = Some(Arc::new(open(&dir.0)));
            }
        }
        stop.store(true, Ordering::Relaxed);
    });
    let rounds = rounds.load(Ordering::Relaxed);
    println!("soak: {rounds} rounds in {secs}s");
    assert!(rounds > 0);
    assert!(matches!(current().health(), nex_db::Health::Ready));
}
