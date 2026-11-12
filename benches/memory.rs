//! Memory per session and per route through the engines, counted by a
//! counting allocator. Prints its results; nothing is timed.
//!
//! ```text
//! cargo bench --bench memory
//! NEX_BENCH_LARGE=1 cargo bench --bench memory   # a million of each
//! ```

use mod_alloc::{ModAlloc, Profiler};
use nex_db::{Database, Entity, SessionSpec};

#[global_allocator]
static GLOBAL: ModAlloc = ModAlloc::new();

fn main() {
    // Run only as a benchmark (`cargo bench` passes `--bench`), not when
    // `cargo test` runs the bench targets.
    if !std::env::args().any(|a| a == "--bench") {
        return;
    }
    let n: usize = if std::env::var_os("NEX_BENCH_LARGE").is_some() {
        1_000_000
    } else {
        100_000
    };
    let dir = std::env::temp_dir().join(format!(
        "nex-db-bench-memory-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    {
        let db = Database::builder(&dir).max_sessions(n + 1).open().unwrap();
        let password = db.auth().hash_password("bench password").unwrap();
        // Accounts of 1,000 sessions each (an account's most), made before
        // the count starts.
        let ids: Vec<usize> = (0..n.div_ceil(1_000)).collect();
        let accounts: Vec<nex_db::AccountId> = ids
            .chunks(100)
            .flat_map(|chunk| {
                db.commit(|tx| {
                    chunk
                        .iter()
                        .map(|i| {
                            tx.auth()
                                .create_account(&format!("memory{i}@example.com"), &password)
                        })
                        .collect::<nex_db::Result<Vec<_>>>()
                })
                .unwrap()
            })
            .collect();

        let profiler = Profiler::start();
        let mut tokens = Vec::with_capacity(n);
        for &account in &accounts {
            let batch = (n - tokens.len()).min(1_000);
            let issued = db
                .commit(|tx| {
                    (0..batch)
                        .map(|_| tx.auth().issue_session(account, SessionSpec::web()))
                        .collect::<nex_db::Result<Vec<_>>>()
                })
                .unwrap();
            tokens.extend(issued);
        }
        // The tokens are the caller's, not the database's.
        let held = profiler.stop().current_bytes;
        let tokens_bytes =
            (tokens.capacity() * std::mem::size_of::<nex_db::Token>() + tokens.len() * 48) as u64;
        drop(tokens);
        println!(
            "auth/memory_per_session: {n} sessions, {} bytes each (heap held by the database after issuing)",
            held.saturating_sub(tokens_bytes) / n as u64
        );

        let profiler = Profiler::start();
        let mut done = 0;
        while done < n {
            let batch = (n - done).min(1_000);
            db.commit(|tx| {
                for i in done..done + batch {
                    let rid = tx
                        .content()
                        .create(Entity::new("page").path(format!("/page/{i}")))?;
                    let _ = tx.content().publish(rid)?;
                }
                Ok(())
            })
            .unwrap();
            done += batch;
        }
        println!(
            "content/memory_per_page: {n} published pages with routes, {} bytes each (heap held by the database: route, listing, and store memory)",
            profiler.stop().current_bytes / n as u64
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
