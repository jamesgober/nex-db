//! Benchmarks for the 0.1 hot paths.
//!
//! ```text
//! cargo bench --bench core
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
        let dir = std::env::temp_dir().join(format!(
            "nex-db-bench-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        TempDb {
            db: Some(Database::open(&dir).unwrap()),
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

    c.bench_function("auth/validate_hit", |b| {
        b.iter(|| db.auth().validate(black_box(token.as_str())).unwrap());
    });
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
}

criterion_group!(benches, auth, content, core);
criterion_main!(benches);
