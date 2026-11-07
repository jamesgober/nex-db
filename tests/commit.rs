//! Commits across engines, uniqueness, conflicts, and the auth operations.

use std::{path::PathBuf, sync::Arc, thread, time::Duration};

use nex_db::{
    Database, Entity, Error, Login, RevokeReason, SessionSpec, SignIn, Standing, Validation, Value,
};

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

#[test]
fn test_revoke_all_ends_every_session_of_the_account_only() {
    let dir = TempDir::new("revoke-all");
    let db = Database::open(&dir.0).unwrap();
    let password = db.auth().hash_password("pw").unwrap();
    let ann = db
        .auth()
        .create_account("ann@example.com", &password)
        .unwrap();
    let bo = db
        .auth()
        .create_account("bo@example.com", &password)
        .unwrap();
    let a1 = db.auth().issue_session(ann, SessionSpec::web()).unwrap();
    let a2 = db.auth().issue_session(ann, SessionSpec::web()).unwrap();
    let b1 = db.auth().issue_session(bo, SessionSpec::web()).unwrap();

    assert_eq!(db.auth().revoke_all(ann).unwrap(), 2);
    for token in [&a1, &a2] {
        assert_eq!(
            db.auth().validate(token).unwrap(),
            Validation::Revoked {
                reason: RevokeReason::SignedOutEverywhere
            }
        );
    }
    assert!(matches!(
        db.auth().validate(&b1).unwrap(),
        Validation::Valid(_)
    ));
    // A session issued afterwards is valid; signing out again ends it.
    let a3 = db.auth().issue_session(ann, SessionSpec::web()).unwrap();
    assert!(matches!(
        db.auth().validate(&a3).unwrap(),
        Validation::Valid(_)
    ));
    assert_eq!(db.auth().revoke_all(ann).unwrap(), 1);
    assert!(!matches!(
        db.auth().validate(&a3).unwrap(),
        Validation::Valid(_)
    ));
    drop(db);

    // The epochs come back with the log.
    let db = Database::open(&dir.0).unwrap();
    assert!(!matches!(
        db.auth().validate(&a1).unwrap(),
        Validation::Valid(_)
    ));
    assert!(!matches!(
        db.auth().validate(&a3).unwrap(),
        Validation::Valid(_)
    ));
    assert!(matches!(
        db.auth().validate(&b1).unwrap(),
        Validation::Valid(_)
    ));
}

#[test]
fn test_revoke_all_in_one_commit_with_a_new_session_keeps_only_the_new_one() {
    let dir = TempDir::new("revoke-all-tx");
    let db = Database::open(&dir.0).unwrap();
    let password = db.auth().hash_password("pw").unwrap();
    let ann = db
        .auth()
        .create_account("ann@example.com", &password)
        .unwrap();
    let old = db.auth().issue_session(ann, SessionSpec::web()).unwrap();
    let new = db
        .commit(|tx| {
            let _ = tx.auth().revoke_all(ann)?;
            tx.auth().issue_session(ann, SessionSpec::web())
        })
        .unwrap();
    assert!(!matches!(
        db.auth().validate(&old).unwrap(),
        Validation::Valid(_)
    ));
    assert!(matches!(
        db.auth().validate(&new).unwrap(),
        Validation::Valid(_)
    ));
}

#[test]
fn test_rotate_replaces_the_token_and_keeps_the_expiry() {
    let dir = TempDir::new("rotate");
    let db = Database::open(&dir.0).unwrap();
    let password = db.auth().hash_password("pw").unwrap();
    let ann = db
        .auth()
        .create_account("ann@example.com", &password)
        .unwrap();
    let old = db.auth().issue_session(ann, SessionSpec::web()).unwrap();
    let Validation::Valid(before) = db.auth().validate(&old).unwrap() else {
        panic!("valid");
    };
    let new = db.auth().rotate(&old).unwrap();
    assert_eq!(
        db.auth().validate(&old).unwrap(),
        Validation::Revoked {
            reason: RevokeReason::Rotated
        }
    );
    let Validation::Valid(after) = db.auth().validate(&new).unwrap() else {
        panic!("valid");
    };
    assert_eq!(
        (after.account(), after.expires_at()),
        (ann, before.expires_at())
    );
    assert!(matches!(db.auth().rotate(&old), Err(Error::Invalid { .. })));
    assert!(matches!(
        db.auth().rotate("not a token"),
        Err(Error::Invalid { .. })
    ));
}

#[test]
fn test_ban_ends_sessions_and_blocks_sign_in_only_with_the_right_password() {
    let dir = TempDir::new("ban");
    let db = Database::open(&dir.0).unwrap();
    let password = db.auth().hash_password("right pw").unwrap();
    let ann = db
        .auth()
        .create_account("ann@example.com", &password)
        .unwrap();
    let token = db.auth().issue_session(ann, SessionSpec::web()).unwrap();

    db.auth()
        .set_standing(ann, Standing::Banned { reason: 3 }, None)
        .unwrap();
    assert!(!matches!(
        db.auth().validate(&token).unwrap(),
        Validation::Valid(_)
    ));
    assert_eq!(
        db.auth().standing(ann).unwrap(),
        Some(Standing::Banned { reason: 3 })
    );
    assert!(matches!(
        db.auth()
            .sign_in("ann@example.com", "right pw", SessionSpec::web())
            .unwrap(),
        SignIn::LockedOut { until: None }
    ));
    // A wrong password says nothing about the ban.
    assert_eq!(
        db.auth()
            .verify_password("ann@example.com", "wrong")
            .unwrap(),
        Login::Failed
    );
    drop(db);

    // The standing survives a reopen; lifting it lets the account in.
    let db = Database::open(&dir.0).unwrap();
    assert_eq!(
        db.auth().standing(ann).unwrap(),
        Some(Standing::Banned { reason: 3 })
    );
    db.auth().set_standing(ann, Standing::Active, None).unwrap();
    assert_eq!(
        db.auth()
            .verify_password("ann@example.com", "right pw")
            .unwrap(),
        Login::Verified(ann)
    );
    assert_eq!(
        db.auth()
            .standing(nex_db::AccountId::from_bytes([9; 16]))
            .unwrap(),
        None
    );
}

#[test]
fn test_ten_failures_lock_the_account_out() {
    let dir = TempDir::new("lockout");
    let db = Database::open(&dir.0).unwrap();
    let password = db.auth().hash_password("right pw").unwrap();
    let ann = db
        .auth()
        .create_account("ann@example.com", &password)
        .unwrap();
    let token = db.auth().issue_session(ann, SessionSpec::web()).unwrap();
    for _ in 0..9 {
        assert_eq!(
            db.auth()
                .verify_password("ann@example.com", "wrong")
                .unwrap(),
            Login::Failed
        );
    }
    // Nine failures: still open.
    assert!(matches!(
        db.auth().validate(&token).unwrap(),
        Validation::Valid(_)
    ));
    assert_eq!(db.auth().standing(ann).unwrap(), Some(Standing::Active));
    assert_eq!(
        db.auth()
            .verify_password("ann@example.com", "wrong")
            .unwrap(),
        Login::Failed
    );
    assert!(matches!(
        db.auth().standing(ann).unwrap(),
        Some(Standing::LockedOut { .. })
    ));
    assert!(!matches!(
        db.auth().validate(&token).unwrap(),
        Validation::Valid(_)
    ));
    assert!(matches!(
        db.auth()
            .verify_password("ann@example.com", "right pw")
            .unwrap(),
        Login::LockedOut { until: Some(_) }
    ));
}

#[test]
fn test_suspension_that_ran_out_reads_as_active() {
    let dir = TempDir::new("suspension");
    let db = Database::open(&dir.0).unwrap();
    let password = db.auth().hash_password("right pw").unwrap();
    let ann = db
        .auth()
        .create_account("ann@example.com", &password)
        .unwrap();
    let past = std::time::SystemTime::now() - Duration::from_secs(60);
    db.auth()
        .set_standing(
            ann,
            Standing::Suspended {
                until: Some(past),
                reason: 1,
            },
            None,
        )
        .unwrap();
    assert_eq!(db.auth().standing(ann).unwrap(), Some(Standing::Active));
    assert!(matches!(
        db.auth()
            .sign_in("ann@example.com", "right pw", SessionSpec::web())
            .unwrap(),
        SignIn::Success { .. }
    ));
}

#[test]
fn test_read_sees_one_snapshot_while_others_commit() {
    let dir = TempDir::new("read-snapshot");
    let db = Database::open(&dir.0).unwrap();
    let password = db.auth().hash_password("pw").unwrap();
    let ann = db
        .auth()
        .create_account("ann@example.com", &password)
        .unwrap();
    let first = db
        .content()
        .create(Entity::new("page").path("/first"))
        .unwrap();

    let (late, seen) = db
        .read(|r| {
            assert_eq!(r.auth().standing(ann)?, Some(Standing::Active));
            // Another thread commits while the snapshot runs.
            let late = std::thread::scope(|s| {
                s.spawn(|| {
                    db.auth()
                        .set_standing(ann, Standing::Banned { reason: 1 }, None)
                        .unwrap();
                    db.content()
                        .create(Entity::new("page").path("/late"))
                        .unwrap()
                })
                .join()
                .unwrap()
            });
            let seen = (
                r.auth().standing(ann)?,
                r.content().get(first)?.is_some(),
                r.content().get(late)?.is_some(),
                r.content()
                    .resolve(nex_db::DEFAULT_SITE, "/late")?
                    .is_some(),
            );
            Ok((late, seen))
        })
        .unwrap();
    assert_eq!(seen, (Some(Standing::Active), true, false, false));

    // A new snapshot sees the commits.
    let now = db
        .read(|r| {
            Ok((
                r.auth().standing(ann)?,
                r.content().get(late)?.is_some(),
                r.content()
                    .resolve(nex_db::DEFAULT_SITE, "/late")?
                    .is_some(),
            ))
        })
        .unwrap();
    assert_eq!(now, (Some(Standing::Banned { reason: 1 }), true, true));
}

#[test]
fn test_session_carries_payload_recheck_and_idle_limit() {
    let dir = TempDir::new("session-spec");
    let db = Database::open(&dir.0).unwrap();
    let password = db.auth().hash_password("pw").unwrap();
    let ann = db
        .auth()
        .create_account("ann@example.com", &password)
        .unwrap();
    let spec = SessionSpec::web()
        .recheck_after(Duration::from_secs(300))
        .payload(b"perm=editor")
        .unwrap();
    let token = db.auth().issue_session(ann, spec).unwrap();
    let Validation::Valid(session) = db.auth().validate(&token).unwrap() else {
        panic!("valid");
    };
    assert_eq!(session.payload(), b"perm=editor");
    assert!(session.recheck_at().is_some());
    assert_eq!(session.idle_limit(), None);

    // Rotation keeps the payload.
    let rotated = db.auth().rotate(&token).unwrap();
    let Validation::Valid(after) = db.auth().validate(&rotated).unwrap() else {
        panic!("valid");
    };
    assert_eq!(after.payload(), b"perm=editor");

    // An idle limit ends a session left unused.
    let idle = db
        .auth()
        .issue_session(ann, SessionSpec::web().idle(Duration::from_secs(1)))
        .unwrap();
    assert!(matches!(
        db.auth().validate(&idle).unwrap(),
        Validation::Valid(_)
    ));
    // A slow disk can take tens of milliseconds to sync the issuing commit,
    // so the limit is long enough for that and the wait longer still. A
    // loaded machine's clock can also be stepped back mid-wait (seen in
    // WSL), so a few waits are allowed; each valid read counts as a use and
    // starts the idle time again, so only a limit that never ends a session
    // fails here.
    let mut outcome = Validation::Unknown;
    for _ in 0..5 {
        thread::sleep(Duration::from_millis(1300));
        outcome = db.auth().validate(&idle).unwrap();
        if outcome == Validation::Expired {
            break;
        }
    }
    assert_eq!(outcome, Validation::Expired);
    assert!(SessionSpec::web().payload(&[0; 257]).is_err());
}

#[test]
fn test_max_sessions_refuses_past_the_limit_and_survives_reopen() {
    let dir = TempDir::new("max-sessions");
    let open = || Database::builder(&dir.0).max_sessions(3).open().unwrap();
    let db = open();
    let password = db.auth().hash_password(PASSWORD).unwrap();
    let ann = db
        .auth()
        .create_account("ann@example.com", &password)
        .unwrap();
    let tokens: Vec<_> = (0..3)
        .map(|_| db.auth().issue_session(ann, SessionSpec::web()).unwrap())
        .collect();
    let err = db
        .auth()
        .issue_session(ann, SessionSpec::web())
        .unwrap_err();
    assert!(matches!(err, Error::Busy { .. }), "{err:?}");
    // A revocation keeps its slot until the session would have expired.
    assert!(db.auth().revoke(&tokens[0]).unwrap());
    assert!(db.auth().issue_session(ann, SessionSpec::web()).is_err());
    drop(db);

    let db = open();
    assert!(matches!(
        db.auth().validate(&tokens[0]).unwrap(),
        Validation::Revoked { .. }
    ));
    for token in &tokens[1..] {
        assert!(matches!(
            db.auth().validate(token).unwrap(),
            Validation::Valid(_)
        ));
    }
    assert!(db.auth().issue_session(ann, SessionSpec::web()).is_err());
}

#[test]
fn test_many_sessions_across_table_levels_validate_after_reopen() {
    let dir = TempDir::new("many-sessions");
    let db = Database::open(&dir.0).unwrap();
    let password = db.auth().hash_password(PASSWORD).unwrap();
    let ann = db
        .auth()
        .create_account("ann@example.com", &password)
        .unwrap();
    // More than the table's first levels hold, so it grows.
    let tokens: Vec<_> = (0..20)
        .flat_map(|_| {
            db.commit(|tx| {
                (0..1_000)
                    .map(|_| tx.auth().issue_session(ann, SessionSpec::web()))
                    .collect::<nex_db::Result<Vec<_>>>()
            })
            .unwrap()
        })
        .collect();
    for token in tokens.iter().step_by(97) {
        assert!(db.auth().revoke(token).unwrap());
    }
    let check = |db: &Database| {
        for (i, token) in tokens.iter().enumerate() {
            let outcome = db.auth().validate(token).unwrap();
            if i % 97 == 0 {
                assert!(matches!(outcome, Validation::Revoked { .. }), "{i}");
            } else {
                assert!(matches!(outcome, Validation::Valid(_)), "{i}");
            }
        }
    };
    check(&db);
    assert_eq!(db.auth().revoke_all(ann).unwrap(), 20_000 - 207);
    drop(db);
    let db = Database::open(&dir.0).unwrap();
    for token in &tokens {
        assert!(matches!(
            db.auth().validate(token).unwrap(),
            Validation::Revoked { .. }
        ));
    }
}
