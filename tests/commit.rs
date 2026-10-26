//! Commits across engines, uniqueness, conflicts, and the auth operations.

use std::{path::PathBuf, sync::Arc, thread, time::Duration};

use nex_db::{Database, Entity, Error, RevokeReason, SessionSpec, SignIn, Validation, Value};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "nex-db-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const PASSWORD: &str = "correct horse battery staple";

#[test]
fn test_commit_account_and_profile_lands_in_both_engines() {
    let dir = TempDir::new("both");
    let db = Database::open(&dir.0).unwrap();
    let password = db.auth().hash_password(PASSWORD).unwrap();
    let (account, rid) = db
        .commit(|tx| {
            let account = tx.auth().create_account("ann@example.com", &password)?;
            let rid = tx.content().create(
                Entity::new("profile")
                    .field("account", account)
                    .field("display_name", "Ann")
                    .site("example.com")
                    .path("/u/ann"),
            )?;
            Ok((account, rid))
        })
        .unwrap();

    let route = db
        .content()
        .resolve("example.com", "/u/ann")
        .unwrap()
        .unwrap();
    assert_eq!(route.entity(), rid);
    assert_eq!(route.revision(), 1);
    let entry = db.content().get(rid).unwrap().unwrap();
    assert_eq!(entry.kind(), "profile");
    assert_eq!(
        entry.field("account").and_then(Value::as_account),
        Some(account)
    );
    assert_eq!(entry.route(), Some(("example.com", "/u/ann")));

    match db
        .auth()
        .sign_in("ann@example.com", PASSWORD, SessionSpec::web())
        .unwrap()
    {
        SignIn::Success {
            account: signed,
            token,
        } => {
            assert_eq!(signed, account);
            let check = db.auth().validate(&token).unwrap();
            assert_eq!(check.session().map(|s| s.account()), Some(account));
        }
        other => panic!("expected success, got {other:?}"),
    }
}

#[test]
fn test_commit_closure_error_writes_nothing() {
    let dir = TempDir::new("abort");
    let db = Database::open(&dir.0).unwrap();
    let password = db.auth().hash_password(PASSWORD).unwrap();
    let result: nex_db::Result<()> = db.commit(|tx| {
        let _ = tx.auth().create_account("bob@example.com", &password)?;
        let _ = tx.content().create(Entity::new("profile").path("/u/bob"))?;
        Err(Error::Invalid {
            field: "test",
            reason: "abort",
        })
    });
    assert!(matches!(result, Err(Error::Invalid { field: "test", .. })));
    assert!(
        db.content()
            .resolve(nex_db::DEFAULT_SITE, "/u/bob")
            .unwrap()
            .is_none()
    );
    // The identifier is still free.
    db.auth()
        .create_account("bob@example.com", &password)
        .unwrap();
}

#[test]
fn test_create_account_taken_identifier_already_exists() {
    let dir = TempDir::new("dup-id");
    let db = Database::open(&dir.0).unwrap();
    let password = db.auth().hash_password(PASSWORD).unwrap();
    db.auth()
        .create_account("Ann@Example.com", &password)
        .unwrap();
    let again = db.auth().create_account("  ann@example.COM ", &password);
    assert!(matches!(
        again,
        Err(Error::AlreadyExists { what: "identifier" })
    ));
    let twice_in_one = db.commit(|tx| {
        let _ = tx.auth().create_account("cy@example.com", &password)?;
        tx.auth().create_account("cy@example.com", &password)
    });
    assert!(matches!(
        twice_in_one,
        Err(Error::AlreadyExists { what: "identifier" })
    ));
}

#[test]
fn test_create_taken_path_already_exists() {
    let dir = TempDir::new("dup-path");
    let db = Database::open(&dir.0).unwrap();
    let _ = db.content().create(Entity::new("page").path("/a")).unwrap();
    assert!(matches!(
        db.content().create(Entity::new("page").path("/a")),
        Err(Error::AlreadyExists { what: "path" })
    ));
    // The same path on another site is free.
    let _ = db
        .content()
        .create(Entity::new("page").site("other.example").path("/a"))
        .unwrap();
}

#[test]
fn test_concurrent_creates_of_one_path_exactly_one_wins() {
    let dir = TempDir::new("race");
    let db = Arc::new(Database::open(&dir.0).unwrap());
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let db = Arc::clone(&db);
            thread::spawn(move || {
                db.content().create(
                    Entity::new("page")
                        .field("writer", i64::from(i))
                        .path("/race"),
                )
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let won = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(won, 1, "{results:?}");
    assert!(results.iter().all(|r| matches!(
        r,
        Ok(_) | Err(Error::AlreadyExists { what: "path" }) | Err(Error::Conflict)
    )));
}

#[test]
fn test_validate_every_outcome() {
    let dir = TempDir::new("validate");
    let db = Database::open(&dir.0).unwrap();
    let password = db.auth().hash_password(PASSWORD).unwrap();
    let account = db
        .auth()
        .create_account("dee@example.com", &password)
        .unwrap();

    assert_eq!(
        db.auth().validate("nonsense").unwrap(),
        Validation::Malformed
    );
    assert_eq!(
        db.auth().validate("A".repeat(48)).unwrap(),
        Validation::Malformed
    );

    let token = db
        .auth()
        .issue_session(account, SessionSpec::web())
        .unwrap();
    assert!(matches!(
        db.auth().validate(&token).unwrap(),
        Validation::Valid(s) if s.account() == account
    ));

    let other_db_dir = TempDir::new("validate-other");
    let other = Database::open(&other_db_dir.0).unwrap();
    // A well-formed token from another database is unknown here.
    assert_eq!(other.auth().validate(&token).unwrap(), Validation::Unknown);

    assert!(db.auth().revoke(&token).unwrap());
    assert!(!db.auth().revoke(&token).unwrap());
    assert_eq!(
        db.auth().validate(&token).unwrap(),
        Validation::Revoked {
            reason: RevokeReason::Revoked
        }
    );

    let short = SessionSpec::new(Duration::from_millis(1)).unwrap();
    let token = db.auth().issue_session(account, short).unwrap();
    thread::sleep(Duration::from_millis(20));
    assert_eq!(db.auth().validate(&token).unwrap(), Validation::Expired);
}

#[test]
fn test_sign_in_wrong_password_and_unknown_identifier_fail() {
    let dir = TempDir::new("sign-in");
    let db = Database::open(&dir.0).unwrap();
    let password = db.auth().hash_password(PASSWORD).unwrap();
    let _ = db
        .auth()
        .create_account("eve@example.com", &password)
        .unwrap();
    assert!(matches!(
        db.auth()
            .sign_in("eve@example.com", "wrong", SessionSpec::web())
            .unwrap(),
        SignIn::Failed
    ));
    assert!(matches!(
        db.auth()
            .sign_in("nobody@example.com", PASSWORD, SessionSpec::web())
            .unwrap(),
        SignIn::Failed
    ));
    assert!(matches!(
        db.auth().sign_in("eve@example.com", "", SessionSpec::web()),
        Err(Error::Invalid { .. })
    ));
}

#[test]
fn test_issue_session_unknown_account_is_invalid() {
    let dir = TempDir::new("no-account");
    let db = Database::open(&dir.0).unwrap();
    let account = nex_db::AccountId::from_bytes([5; 16]);
    assert!(matches!(
        db.auth().issue_session(account, SessionSpec::web()),
        Err(Error::Invalid {
            field: "account",
            ..
        })
    ));
}

#[test]
fn test_commit_with_nothing_staged_writes_nothing() {
    let dir = TempDir::new("empty");
    let db = Database::open(&dir.0).unwrap();
    let value = db.commit(|_tx| Ok(7)).unwrap();
    assert_eq!(value, 7);
}

#[test]
fn test_open_second_owner_is_locked() {
    let dir = TempDir::new("locked");
    let db = Database::open(&dir.0).unwrap();
    assert!(matches!(Database::open(&dir.0), Err(Error::Locked)));
    drop(db);
    let _again = Database::open(&dir.0).unwrap();
}

#[test]
fn test_secrets_never_in_debug_output() {
    let dir = TempDir::new("debug");
    let db = Database::open(&dir.0).unwrap();
    let password = db.auth().hash_password(PASSWORD).unwrap();
    let account = db
        .auth()
        .create_account("fay@example.com", &password)
        .unwrap();
    let token = db
        .auth()
        .issue_session(account, SessionSpec::web())
        .unwrap();
    let shown = format!("{password:?} {token:?} {db:?}");
    assert!(!shown.contains(token.as_str()));
    assert!(!shown.contains("argon2"));
}
