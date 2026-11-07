//! Benchmarks for the hot paths.
//!
//! ```text
//! cargo bench --bench core
//! NEX_BENCH_LARGE=1 cargo bench --bench core   # also 10 million sessions
//! ```

use std::{
    hint::black_box,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use nex_db::{Database, Entity, SessionSpec};

struct TempDb {
    db: Option<Database>,
    dir: PathBuf,
}

impl TempDb {
    fn new(name: &str) -> Self {
        Self::with(name, |b| b)
    }

    fn with(name: &str, f: impl FnOnce(nex_db::Builder) -> nex_db::Builder) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "nex-db-bench-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        TempDb {
            db: Some(f(Database::builder(&dir)).open().unwrap()),
            dir,
        }
    }

    fn db(&self) -> &Database {
        self.db.as_ref().unwrap()
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        drop(self.db.take());
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique() -> u64 {
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn auth(c: &mut Criterion) {
    let t = TempDb::new("auth");
    let db = t.db();
    let password = db.auth().hash_password("bench password").unwrap();
    let account = db
        .auth()
        .create_account("bench@example.com", &password)
        .unwrap();
    let token = db
        .auth()
        .issue_session(account, SessionSpec::web())
        .unwrap();

    let mut group = c.benchmark_group("auth/validate_hit");
    let _ = group.bench_function("1", |b| {
        b.iter(|| db.auth().validate(black_box(token.as_str())).unwrap());
    });
    group.finish();
    validate_many(c);
    c.bench_function("auth/issue_durable", |b| {
        b.iter(|| {
            db.auth()
                .issue_session(account, SessionSpec::web())
                .unwrap()
        });
    });
    c.bench_function("auth/revoke_durable", |b| {
        b.iter_batched(
            || {
                db.auth()
                    .issue_session(account, SessionSpec::web())
                    .unwrap()
            },
            |token| db.auth().revoke(&token).unwrap(),
            BatchSize::SmallInput,
        );
    });
    let mut group = c.benchmark_group("auth");
    let _ = group.sample_size(10);
    let _ = group.bench_function("sign_in", |b| {
        b.iter(|| {
            db.auth()
                .sign_in("bench@example.com", "bench password", SessionSpec::web())
                .unwrap()
        });
    });
    group.finish();
}

/// `auth/validate_hit` over a table of one and ten million sessions, each
/// iteration a different token in a scattered order, so most reads miss the
/// CPU cache as they would on a busy site.
fn validate_many(c: &mut Criterion) {
    let mut sizes = vec![1_000_000usize];
    if std::env::var_os("NEX_BENCH_LARGE").is_some() {
        sizes.push(10_000_000);
    }
    for n in sizes {
        let t = TempDb::with("validate", |b| b.max_sessions(n + 1));
        let db = t.db();
        let password = db.auth().hash_password("bench password").unwrap();
        let account = db
            .auth()
            .create_account("many@example.com", &password)
            .unwrap();
        let mut tokens = Vec::with_capacity(n);
        while tokens.len() < n {
            let batch = (n - tokens.len()).min(4_000);
            let issued = db
                .commit(|tx| {
                    (0..batch)
                        .map(|_| tx.auth().issue_session(account, SessionSpec::web()))
                        .collect::<nex_db::Result<Vec<_>>>()
                })
                .unwrap();
            tokens.extend(issued);
        }
        let mut group = c.benchmark_group("auth/validate_hit");
        let mut i = 0usize;
        let _ = group.bench_function(format!("{n}"), |b| {
            b.iter(|| {
                // A step coprime with n visits every token once per n reads.
                i = (i + 7_919) % n;
                db.auth().validate(black_box(tokens[i].as_str())).unwrap()
            });
        });
        group.finish();
    }
}

fn content(c: &mut Criterion) {
    let t = TempDb::new("content");
    let db = t.db();
    for i in 0..1_000 {
        let _ = db
            .content()
            .create(
                Entity::new("page")
                    .field("title", "Hello")
                    .path(format!("/p/{i}")),
            )
            .unwrap();
    }
    let route = db
        .content()
        .resolve(nex_db::DEFAULT_SITE, "/p/500")
        .unwrap()
        .unwrap();

    c.bench_function("content/resolve_exact", |b| {
        b.iter(|| {
            db.content()
                .resolve(black_box(nex_db::DEFAULT_SITE), black_box("/p/500"))
                .unwrap()
        });
    });
    c.bench_function("content/get_warm", |b| {
        b.iter(|| db.content().get(black_box(route.entity())).unwrap());
    });
}

fn core(c: &mut Criterion) {
    let t = TempDb::new("core");
    let db = t.db();
    let password = db.auth().hash_password("bench password").unwrap();
    c.bench_function("core/commit_cross_engine", |b| {
        b.iter(|| {
            let i = unique();
            db.commit(|tx| {
                let account = tx
                    .auth()
                    .create_account(&format!("x{i}@example.com"), &password)?;
                tx.content().create(
                    Entity::new("profile")
                        .field("account", account)
                        .path(format!("/u/{i}")),
                )
            })
            .unwrap()
        });
    });

    // Commits per second with 1 to 64 writers: each iteration runs one
    // commit on every writer at once, so group commit can share syncs.
    let t = TempDb::new("throughput");
    let db = t.db();
    let mut group = c.benchmark_group("core/commit_throughput");
    for writers in [1u64, 4, 16, 64] {
        let _ = group.throughput(criterion::Throughput::Elements(writers));
        let _ = group.bench_function(format!("{writers}"), |b| {
            b.iter(|| {
                std::thread::scope(|s| {
                    for _ in 0..writers {
                        s.spawn(|| {
                            let i = unique();
                            db.commit(|tx| {
                                tx.content()
                                    .create(Entity::new("note").path(format!("/n/{i}")))
                            })
                            .unwrap()
                        });
                    }
                });
            });
        });
    }
    group.finish();
}

criterion_group!(benches, auth, content, core);
criterion_main!(benches);
