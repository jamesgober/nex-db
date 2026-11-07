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
                let rid = tx.content().create(
                    Entity::new("profile")
                        .field("account", account)
                        .path(format!("/u/{i}")),
                )?;
                let _ = tx.content().publish(rid)?;
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
fn test_reopen_damage_before_the_tail_stays_closed_and_leaves_the_log() {
    let dir = TempDir::new("mid-log");
    let db = Database::open(&dir.0).unwrap();
    let _ = populate(&db, 0, 5);
    drop(db);

    let segment = first_segment(&dir.0);
    let mut bytes = fs::read(&segment).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0xff;
    fs::write(&segment, &bytes).unwrap();

    assert!(matches!(Database::open(&dir.0), Err(Error::Corrupt { .. })));
    // Refused, not repaired: the records after the damage are still there.
    assert_eq!(fs::read(&segment).unwrap(), bytes);
    assert!(matches!(Database::open(&dir.0), Err(Error::Corrupt { .. })));
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

/// Every file under `dir`, read whole.
fn all_bytes(dir: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(all_bytes(&path));
        } else {
            out.extend(fs::read(&path).unwrap());
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn test_files_hold_no_password_hash_or_identifier() {
    let dir = TempDir::new("sealed");
    let db = Database::open(&dir.0).unwrap();
    let _ = populate(&db, 0, 3);
    // Dropping writes the account store to its own files.
    drop(db);
    let log = all_bytes(&dir.0.join("core").join("log"));
    let accounts = all_bytes(&dir.0.join("auth").join("accounts"));
    assert!(!log.is_empty() && !accounts.is_empty());
    for bytes in [&log, &accounts] {
        assert!(!contains(bytes, b"$argon2id$"));
        assert!(!contains(bytes, b"u1@example.com"));
    }
    // Sign-in still reads the sealed record.
    let db = Database::open(&dir.0).unwrap();
    assert!(matches!(
        db.auth()
            .sign_in("u1@example.com", PASSWORD, SessionSpec::web())
            .unwrap(),
        SignIn::Success { .. }
    ));
}

#[test]
fn test_key_outside_the_directory_is_needed_to_open() {
    let dir = TempDir::new("key-file");
    let key_dir = TempDir::new("key-file-key");
    fs::create_dir_all(&key_dir.0).unwrap();
    let key = key_dir.0.join("site.key");
    {
        let db = Database::builder(&dir.0)
            .keys(nex_db::Keys::file(&key))
            .open()
            .unwrap();
        let _ = populate(&db, 0, 1);
    }
    assert!(key.exists());
    assert!(!dir.0.join("auth").join("keys").exists());
    // The directory alone does not open, and neither does another key.
    assert!(matches!(Database::open(&dir.0), Err(Error::KeyUnavailable)));
    let other = key_dir.0.join("other.key");
    assert!(matches!(
        Database::builder(&dir.0)
            .keys(nex_db::Keys::file(&other))
            .open(),
        Err(Error::KeyUnavailable)
    ));
    // The right key opens it with everything in place.
    let db = Database::builder(&dir.0)
        .keys(nex_db::Keys::file(&key))
        .open()
        .unwrap();
    assert!(matches!(
        db.auth()
            .sign_in("u0@example.com", PASSWORD, SessionSpec::web())
            .unwrap(),
        SignIn::Success { .. }
    ));
}

fn checkpointing(dir: &Path) -> Database {
    // A checkpoint, with truncation, after every commit.
    Database::builder(dir).checkpoint_every(1).open().unwrap()
}

#[test]
fn test_truncated_log_reopens_with_everything() {
    let dir = TempDir::new("truncated");
    let tokens = {
        let db = checkpointing(&dir.0);
        let tokens = populate(&db, 0, 6);
        assert!(db.auth().revoke(&tokens[1]).unwrap());
        let account = match db.auth().validate(&tokens[2]).unwrap() {
            Validation::Valid(s) => s.account(),
            other => panic!("{other:?}"),
        };
        let _ = db.auth().revoke_all(account).unwrap();
        tokens
    };
    let db = Database::open(&dir.0).unwrap();
    assert!(matches!(
        db.auth().validate(&tokens[0]).unwrap(),
        Validation::Valid(_)
    ));
    assert_eq!(
        db.auth().validate(&tokens[1]).unwrap(),
        Validation::Revoked {
            reason: RevokeReason::Revoked
        }
    );
    assert_eq!(
        db.auth().validate(&tokens[2]).unwrap(),
        Validation::Revoked {
            reason: RevokeReason::SignedOutEverywhere
        }
    );
    assert!(matches!(
        db.auth()
            .sign_in("u5@example.com", PASSWORD, SessionSpec::web())
            .unwrap(),
        SignIn::Success { .. }
    ));
    assert!(
        db.content()
            .resolve(nex_db::DEFAULT_SITE, "/u/5")
            .unwrap()
            .is_some()
    );
    drop(db);

    // The log no longer starts at the first commit: without its file, the
    // catalog cannot be rebuilt, and the database stays closed.
    fs::remove_file(dir.0.join("core").join("catalog.ckpt")).unwrap();
    assert!(matches!(Database::open(&dir.0), Err(Error::Corrupt { .. })));
}

#[test]
fn test_truncated_log_without_its_session_checkpoint_stays_closed() {
    let dir = TempDir::new("no-sessions");
    {
        let db = checkpointing(&dir.0);
        let _ = populate(&db, 0, 3);
    }
    let file = dir.0.join("auth").join("sessions.ckpt");
    let mut bytes = fs::read(&file).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&file, &bytes).unwrap();
    assert!(matches!(Database::open(&dir.0), Err(Error::Corrupt { .. })));
    fs::remove_file(&file).unwrap();
    assert!(matches!(Database::open(&dir.0), Err(Error::Corrupt { .. })));
}

#[test]
fn test_session_payload_survives_a_checkpoint() {
    let dir = TempDir::new("payload-ckpt");
    let token = {
        let db = checkpointing(&dir.0);
        let password = db.auth().hash_password(PASSWORD).unwrap();
        let ann = db
            .auth()
            .create_account("ann@example.com", &password)
            .unwrap();
        let spec = SessionSpec::web().payload(b"perm=admin").unwrap();
        let token = db.auth().issue_session(ann, spec).unwrap();
        // One more commit, so the checkpoint after it holds the session.
        let _ = populate(&db, 0, 1);
        token
    };
    let db = Database::open(&dir.0).unwrap();
    match db.auth().validate(&token).unwrap() {
        Validation::Valid(session) => assert_eq!(session.payload(), b"perm=admin"),
        other => panic!("{other:?}"),
    }
}
