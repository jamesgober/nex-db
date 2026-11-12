//! Read hits allocate nothing: a session check, a route lookup, and a read
//! of a published entry already read once, counted by a counting allocator.
//! With `split-auth`, a session check through the auth process allocates
//! nothing in the application either.
//!
//! Runs without the test harness, so nothing else in the process allocates
//! while it counts.

use mod_alloc::{ModAlloc, Profiler};
use nex_db::{DEFAULT_SITE, Database, Entity, SessionSpec, Validation};

#[global_allocator]
static GLOBAL: ModAlloc = ModAlloc::new();

const ROUNDS: u64 = 1_000;

/// Allocations `f` makes over [`ROUNDS`] calls, after one call to warm up.
fn allocations(mut f: impl FnMut()) -> u64 {
    f();
    let profiler = Profiler::start();
    for _ in 0..ROUNDS {
        f();
    }
    profiler.stop().alloc_count
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "nex-db-alloc-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// Before 0.8 each split check made 4 allocations in the application (the
/// request frame, its growth, the slot it waited in, and the reply's
/// buffer), all freed unwiped. Now a thread reuses them.
#[cfg(feature = "split-auth")]
fn split() {
    let dir = temp_dir("split");
    {
        let db = Database::builder(&dir)
            .auth(nex_db::AuthMode::separate_process())
            .open()
            .unwrap();
        let password = db.auth().hash_password("alloc password").unwrap();
        let account = db
            .auth()
            .create_account("alloc@example.com", &password)
            .unwrap();
        let token = db
            .auth()
            .issue_session(account, SessionSpec::web())
            .unwrap();
        // The count is of the whole process, and 1,000 round trips give the
        // watchdog and the scheduler time to run: the fewest of three
        // windows (an allocation per check shows in every one).
        let validate = (0..3)
            .map(|_| {
                allocations(|| {
                    let v = db.auth().validate(token.as_str()).unwrap();
                    assert!(matches!(v, Validation::Valid(_)));
                })
            })
            .min()
            .unwrap_or(u64::MAX);
        println!("allocations per {ROUNDS} split reads: validate {validate}");
        assert_eq!(validate, 0, "a split validate allocates");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn main() {
    #[cfg(feature = "split-auth")]
    if nex_db::serve_auth_process().unwrap() {
        return;
    }
    let dir = temp_dir("embedded");
    {
        let db = Database::open(&dir).unwrap();
        let password = db.auth().hash_password("alloc password").unwrap();
        let account = db
            .auth()
            .create_account("alloc@example.com", &password)
            .unwrap();
        let token = db
            .auth()
            .issue_session(account, SessionSpec::web())
            .unwrap();
        let rid = db
            .content()
            .create(Entity::new("page").field("title", "Hello").path("/hello"))
            .unwrap();
        let _ = db.content().publish(rid).unwrap();

        let validate = allocations(|| {
            let v = db.auth().validate(token.as_str()).unwrap();
            assert!(matches!(v, Validation::Valid(_)));
        });
        let resolve = allocations(|| {
            let route = db.content().resolve(DEFAULT_SITE, "/hello").unwrap();
            assert!(route.is_some());
        });
        let get = allocations(|| {
            let entry = db.content().get(rid).unwrap();
            assert!(entry.is_some());
        });
        // Version 1, every other byte zero: well formed, never issued.
        let stranger = format!("AQAA{}", "A".repeat(44));
        let unknown = allocations(|| {
            let v = db.auth().validate(stranger.as_str()).unwrap();
            assert!(matches!(v, Validation::Unknown));
        });
        println!(
            "allocations per {ROUNDS} reads: validate {validate}, unknown token {unknown}, \
             resolve {resolve}, get {get}"
        );
        assert_eq!(validate, 0, "validate allocates");
        assert_eq!(unknown, 0, "validate of an unknown token allocates");
        assert_eq!(resolve, 0, "resolve allocates");
        assert_eq!(get, 0, "a cached get allocates");
    }
    let _ = std::fs::remove_dir_all(&dir);
    #[cfg(feature = "split-auth")]
    split();
    println!("alloc: ok");
}
