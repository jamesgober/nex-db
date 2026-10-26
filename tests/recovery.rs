//! Reopening: state survives, damage keeps the database closed.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use nex_db::{Database, Entity, Error, RevokeReason, SessionSpec, SignIn, Validation};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        TempDir(std::env::temp_dir().join(format!(
            "nex-db-recovery-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const PASSWORD: &str = "correct horse battery staple";

fn first_segment(dir: &Path) -> PathBuf {
    dir.join("core")
        .join("log")
        .join("00000000000000000000.wal")
}

/// Sign up users `start..start + n`; return their tokens.
fn populate(db: &Database, start: usize, n: usize) -> Vec<nex_db::Token> {
    let password = db.auth().hash_password(PASSWORD).unwrap();
    (start..start + n)
        .map(|i| {
            db.commit(|tx| {
                let account = tx
                    .auth()
                    .create_account(&format!("u{i}@example.com"), &password)?;
                let _ = tx.content().create(
                    Entity::new("profile")
                        .field("account", account)
                        .path(format!("/u/{i}")),
                )?;
                tx.auth().issue_session(account, SessionSpec::web())
            })
            .unwrap()
        })
        .collect()
}

#[test]
fn test_reopen_keeps_accounts_sessions_revocations_and_routes() {
    let dir = TempDir::new("reopen");
    let tokens = {
        let db = Database::open(&dir.0).unwrap();
        let tokens = populate(&db, 0, 5);
        assert!(db.auth().revoke(&tokens[1]).unwrap());
        tokens
    };

    let db = Database::open(&dir.0).unwrap();
    for (i, token) in tokens.iter().enumerate() {
        let check = db.auth().validate(token).unwrap();
        if i == 1 {
            assert_eq!(
                check,
                Validation::Revoked {
                    reason: RevokeReason::Revoked
                }
            );
        } else {
            assert!(
                matches!(check, Validation::Valid(_)),
                "token {i}: {check:?}"
            );
        }
        let route = db
            .content()
            .resolve(nex_db::DEFAULT_SITE, &format!("/u/{i}"))
            .unwrap()
            .unwrap();
        assert!(db.content().get(route.entity()).unwrap().is_some());
    }
    assert!(matches!(
        db.auth()
            .sign_in("u3@example.com", PASSWORD, SessionSpec::web())
            .unwrap(),
        SignIn::Success { .. }
    ));
    // Uniqueness survives too.
    let password = db.auth().hash_password(PASSWORD).unwrap();
    assert!(matches!(
        db.auth().create_account("u0@example.com", &password),
        Err(Error::AlreadyExists { .. })
    ));
}

#[test]
fn test_reopen_three_times_is_stable() {
    let dir = TempDir::new("thrice");
    let token = {
        let db = Database::open(&dir.0).unwrap();
        populate(&db, 0, 1).remove(0)
    };
    for _ in 0..3 {
        let db = Database::open(&dir.0).unwrap();
        assert!(matches!(
            db.auth().validate(&token).unwrap(),
            Validation::Valid(_)
        ));
        let _ = populate(&db, 9, 0);
    }
}

#[test]
fn test_reopen_garbage_after_last_record_is_cut() {
    let dir = TempDir::new("torn");
    let tokens = {
        let db = Database::open(&dir.0).unwrap();
        populate(&db, 0, 3)
    };
    let mut file = OpenOptions::new()
        .append(true)
        .open(first_segment(&dir.0))
        .unwrap();
    file.write_all(&[0xA5; 37]).unwrap();
    drop(file);

    let db = Database::open(&dir.0).unwrap();
    for token in &tokens {
        assert!(matches!(
            db.auth().validate(token).unwrap(),
            Validation::Valid(_)
        ));
    }
    // New commits land after the cut.
    let more = populate(&db, 3, 1);
    drop(db);
    let db = Database::open(&dir.0).unwrap();
    assert!(matches!(
        db.auth().validate(&more[0]).unwrap(),
        Validation::Valid(_)
    ));
}

#[test]
fn test_reopen_log_shorter_than_stores_is_corrupt() {
    let dir = TempDir::new("short");
    {
        let db = Database::open(&dir.0).unwrap();
        let _ = populate(&db, 0, 3);
        // Dropping flushes the stores up to the last commit.
    }
    let segment = first_segment(&dir.0);
    let len = fs::metadata(&segment).unwrap().len();
    let file = OpenOptions::new().write(true).open(&segment).unwrap();
    file.set_len(len - 10).unwrap();
    drop(file);
    assert!(matches!(Database::open(&dir.0), Err(Error::Corrupt { .. })));
}

#[test]
fn test_reopen_missing_key_file_stays_closed() {
    let dir = TempDir::new("nokey");
    drop(Database::open(&dir.0).unwrap());
    fs::remove_file(dir.0.join("auth").join("keys")).unwrap();
    assert!(matches!(Database::open(&dir.0), Err(Error::KeyUnavailable)));
}

#[test]
fn test_reopen_damaged_catalog_stays_closed() {
    let dir = TempDir::new("catalog");
    drop(Database::open(&dir.0).unwrap());
    let path = dir.0.join("core").join("catalog.ckpt");
    let mut bytes = fs::read(&path).unwrap();
    bytes[3] ^= 0x40;
    fs::write(&path, bytes).unwrap();
    assert!(matches!(Database::open(&dir.0), Err(Error::Corrupt { .. })));
}

#[test]
fn test_reopen_missing_log_stays_closed() {
    let dir = TempDir::new("nolog");
    drop(Database::open(&dir.0).unwrap());
    fs::remove_dir_all(dir.0.join("core").join("log")).unwrap();
    assert!(matches!(Database::open(&dir.0), Err(Error::Corrupt { .. })));
}

#[test]
fn test_reopen_missing_catalog_is_rebuilt_from_log() {
    let dir = TempDir::new("rebuild");
    let token = {
        let db = Database::open(&dir.0).unwrap();
        populate(&db, 0, 1).remove(0)
    };
    fs::remove_file(dir.0.join("core").join("catalog.ckpt")).unwrap();
    let db = Database::open(&dir.0).unwrap();
    assert!(matches!(
        db.auth().validate(&token).unwrap(),
        Validation::Valid(_)
    ));
}
