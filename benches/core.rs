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

use criterion::{BatchSize, Criterion, criterion_group};
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
    db.content()
        .define(
            nex_db::Type::new("page")
                .field("title", nex_db::FieldType::Text)
                .searchable(3),
        )
        .unwrap();
    const WORDS: [&str; 8] = [
        "garden", "river", "stone", "light", "winter", "harbor", "forest", "market",
    ];
    for i in 0..1_000 {
        let title = format!("Hello {} {}", WORDS[i % 8], WORDS[(i / 8) % 8]);
        let _ = db
            .commit(|tx| {
                let rid = tx.content().create(
                    Entity::new("page")
                        .field("title", title.as_str())
                        .path(format!("/p/{i}")),
                )?;
                tx.content().publish(rid)
            })
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
    let latest = nex_db::Listing::latest("page").limit(10);
    c.bench_function("content/list_latest", |b| {
        b.iter(|| db.content().list(black_box(&latest)).unwrap());
    });
    // Ten thousand entities read in turn: more than the cache keeps, so
    // most reads decode from the store.
    let many: Vec<nex_db::EntityId> = (0..10_000)
        .map(|i| {
            db.commit(|tx| {
                let rid = tx.content().create(
                    Entity::new("page")
                        .field("title", "many")
                        .path(format!("/m/{i}")),
                )?;
                let _ = tx.content().publish(rid)?;
                Ok(rid)
            })
            .unwrap()
        })
        .collect();
    let mut i = 0usize;
    c.bench_function("content/get_rotating_10k", |b| {
        b.iter(|| {
            i = (i + 7_919) % many.len();
            db.content().get(black_box(many[i])).unwrap()
        });
    });
    let query = nex_db::Search::new("river garden");
    c.bench_function("content/search", |b| {
        b.iter(|| {
            db.content()
                .search(nex_db::Locale::EN, black_box(&query))
                .unwrap()
        });
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
                let rid = tx.content().create(
                    Entity::new("profile")
                        .field("account", account)
                        .path(format!("/u/{i}")),
                )?;
                tx.content().publish(rid)
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
                                let rid = tx
                                    .content()
                                    .create(Entity::new("note").path(format!("/n/{i}")))?;
                                tx.content().publish(rid)
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

/// `auth/validate_split`: a session check with the auth engine in its own
/// process (feature `split-auth`), one round trip over the pipe.
#[cfg(feature = "split-auth")]
fn split(c: &mut Criterion) {
    let t = TempDb::with("split", |b| b.auth(nex_db::AuthMode::separate_process()));
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
    c.bench_function("auth/validate_split", |b| {
        b.iter(|| db.auth().validate(black_box(token.as_str())).unwrap());
    });
    c.bench_function("auth/issue_durable_split", |b| {
        b.iter(|| {
            db.auth()
                .issue_session(account, SessionSpec::web())
                .unwrap()
        });
    });
}

#[cfg(not(feature = "split-auth"))]
fn split(_: &mut Criterion) {}

/// `core/recovery`: closing and opening a database that holds 100,000
/// sessions (a million with `NEX_BENCH_LARGE`) and 1,000 published
/// entities, checkpointed as the default log size triggers it: replay of
/// the last checkpoint and the log after it.
fn recovery(c: &mut Criterion) {
    let n: usize = if std::env::var_os("NEX_BENCH_LARGE").is_some() {
        1_000_000
    } else {
        100_000
    };
    let mut t = TempDb::with("recovery", |b| b.max_sessions(n + 1));
    {
        let db = t.db();
        let password = db.auth().hash_password("bench password").unwrap();
        let account = db
            .auth()
            .create_account("recover@example.com", &password)
            .unwrap();
        for i in 0..1_000 {
            let _ = db
                .commit(|tx| {
                    let rid = tx
                        .content()
                        .create(Entity::new("page").path(format!("/r/{i}")))?;
                    tx.content().publish(rid)
                })
                .unwrap();
        }
        let issue = |count: usize| {
            let mut left: usize = count;
            while left > 0 {
                let batch = left.min(4_000);
                let _ = db
                    .commit(|tx| {
                        (0..batch)
                            .map(|_| tx.auth().issue_session(account, SessionSpec::web()))
                            .collect::<nex_db::Result<Vec<_>>>()
                    })
                    .unwrap();
                left -= batch;
            }
        };
        issue(n);
    }
    let mut group = c.benchmark_group("core/recovery");
    let _ = group.sample_size(10);
    let _ = group.bench_function(format!("{n}"), |b| {
        b.iter(|| {
            drop(t.db.take());
            t.db = Some(
                Database::builder(&t.dir)
                    .max_sessions(n + 1)
                    .open()
                    .unwrap(),
            );
        });
    });
    group.finish();
}

/// `replica/*`: a read replica following its primary. `ship_receive_100`
/// seals 100 commits of one page each on the primary, and opens and commits
/// them on the replica (both on this machine, so each side's syncs count).
/// `commit_not_shipping` and `commit_while_shipping` are one `content().put`
/// before and after the primary first ships: after it, each commit also
/// keeps its record for the next shipment.
fn replica(c: &mut Criterion) {
    let dir = std::env::temp_dir().join(format!(
        "nex-db-bench-replica-{}-{}",
        std::process::id(),
        unique()
    ));
    let primary = Database::open(dir.join("primary")).unwrap();
    let _ = primary
        .content()
        .put(Entity::new("page").path("/seed"))
        .unwrap();
    let _ = primary.backup(dir.join("backup")).unwrap();
    let _ = nex_db::restore(
        dir.join("backup"),
        dir.join("replica"),
        nex_db::RestorePoint::Latest,
    )
    .unwrap();
    let replica = nex_db::open_replica(dir.join("replica")).unwrap();
    c.bench_function("replica/commit_not_shipping", |b| {
        b.iter(|| {
            let i = unique();
            primary
                .content()
                .put(
                    Entity::new("page")
                        .field("n", i as i64)
                        .path(format!("/b/{i}")),
                )
                .unwrap()
        });
    });
    let mut shipment = Vec::new();
    c.bench_function("replica/ship_receive_100", |b| {
        b.iter_batched(
            || {
                for _ in 0..100 {
                    let i = unique();
                    let _ = primary
                        .content()
                        .put(
                            Entity::new("page")
                                .field("n", i as i64)
                                .path(format!("/r/{i}")),
                        )
                        .unwrap();
                }
            },
            |()| {
                shipment.clear();
                let _ = primary.ship(replica.position(), &mut shipment).unwrap();
                black_box(replica.receive(&mut shipment.as_slice()).unwrap())
            },
            BatchSize::PerIteration,
        );
    });
    c.bench_function("replica/commit_while_shipping", |b| {
        b.iter(|| {
            let i = unique();
            primary
                .content()
                .put(
                    Entity::new("page")
                        .field("n", i as i64)
                        .path(format!("/s/{i}")),
                )
                .unwrap()
        });
    });
    drop(replica);
    drop(primary);
    let _ = std::fs::remove_dir_all(&dir);
}

criterion_group!(benches, auth, split, content, core, recovery, replica);

// The bench program is also the auth process of `auth/validate_split`.
fn main() {
    #[cfg(feature = "split-auth")]
    if nex_db::serve_auth_process().unwrap() {
        return;
    }
    benches();
    Criterion::default().configure_from_args().final_summary();
}
