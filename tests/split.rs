//! Split auth: the auth engines in a process of their own.
//!
//! This binary is also the auth process: `main` hands over to
//! `serve_auth_process` when the database started it as one. Tests run one
//! after another; each failure is reported and the run fails at the end.

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use nex_db::{
    ApiKeyCheck, AuthMode, Change, Database, Entity, Error, Health, Keys, Login, Purpose,
    RealmPolicy, RestorePoint, RevokeReason, Role, SessionSpec, SignIn, Standing, Validation,
};

const PASSWORD: &str = "correct horse battery staple";

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        TempDir(std::env::temp_dir().join(format!(
            "nex-db-split-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )))
    }

    fn at(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn split(dir: &Path) -> Database {
    Database::builder(dir)
        .auth(AuthMode::separate_process())
        .open()
        .unwrap()
}

fn embedded(dir: &Path) -> Database {
    Database::open(dir).unwrap()
}

fn sign_up(db: &Database, who: &str) -> nex_db::AccountId {
    let hash = db.auth().hash_password(PASSWORD).unwrap();
    db.auth().create_account(who, &hash).unwrap()
}

fn sign_in(db: &Database, who: &str) -> SignIn {
    db.auth()
        .sign_in(who, PASSWORD, SessionSpec::web())
        .unwrap()
}

fn token_of(sign_in: SignIn) -> nex_db::Token {
    match sign_in {
        SignIn::Success { token, .. } => token,
        other => panic!("not signed in: {other:?}"),
    }
}

fn test_sign_up_across_engines_reopens_in_either_mode() {
    let t = TempDir::new("signup");
    let dir = t.at("db");
    let (account, rid, token) = {
        let db = split(&dir);
        assert!(db.auth_process_id().is_some());
        let hash = db.auth().hash_password(PASSWORD).unwrap();
        let (account, rid) = db
            .commit(|tx| {
                let account = tx.auth().create_account("ann@example.com", &hash)?;
                let rid = tx.content().create(
                    Entity::new("profile")
                        .field("account", account)
                        .path("/u/ann"),
                )?;
                Ok((account, rid))
            })
            .unwrap();
        let token = token_of(sign_in(&db, "ann@example.com"));
        assert!(
            matches!(db.auth().validate(&token).unwrap(), Validation::Valid(s) if s.account() == account)
        );
        (account, rid, token)
    };
    // Split again: everything is back.
    {
        let db = split(&dir);
        assert!(db.auth().account(account).unwrap().is_some());
        assert!(db.content().draft(rid).unwrap().is_some());
        assert!(
            matches!(db.auth().validate(&token).unwrap(), Validation::Valid(s) if s.account() == account)
        );
        let _ = db.auth().create_account(
            "bo@example.com",
            &db.auth().hash_password(PASSWORD).unwrap(),
        );
    }
    // Embedded: the same directory opens, with the same accounts and
    // sessions.
    {
        let db = embedded(&dir);
        assert!(db.auth_process_id().is_none());
        assert!(
            matches!(db.auth().validate(&token).unwrap(), Validation::Valid(s) if s.account() == account)
        );
        assert!(matches!(
            sign_in(&db, "bo@example.com"),
            SignIn::Success { .. }
        ));
        assert!(db.content().draft(rid).unwrap().is_some());
        let _ = sign_up(&db, "cy@example.com");
    }
    // And split once more, after embedded commits.
    let db = split(&dir);
    assert!(matches!(
        sign_in(&db, "cy@example.com"),
        SignIn::Success { .. }
    ));
    assert!(matches!(
        db.auth()
            .sign_in("cy@example.com", "wrong", SessionSpec::web())
            .unwrap(),
        SignIn::Failed
    ));
}

fn test_sessions_revoke_and_standing() {
    let t = TempDir::new("sessions");
    let db = split(&t.at("db"));
    let ann = sign_up(&db, "ann@example.com");
    let one = token_of(sign_in(&db, "ann@example.com"));
    let two = token_of(sign_in(&db, "ann@example.com"));
    assert_eq!(db.auth().sessions(ann).unwrap().len(), 2);
    assert!(db.auth().revoke(&one).unwrap());
    assert!(!db.auth().revoke(&one).unwrap());
    assert_eq!(
        db.auth().validate(&one).unwrap(),
        Validation::Revoked {
            reason: RevokeReason::Revoked
        }
    );
    assert_eq!(
        db.auth().validate("not a token").unwrap(),
        Validation::Malformed
    );
    let rotated = db.auth().rotate(&two).unwrap();
    assert!(db.auth().validate(&rotated).unwrap().session().is_some());
    let listed = db.auth().sessions(ann).unwrap();
    assert_eq!(listed.len(), 1);
    assert!(db.auth().revoke_session(ann, listed[0].id()).unwrap());
    assert!(db.auth().validate(&rotated).unwrap().session().is_none());

    let three = token_of(sign_in(&db, "ann@example.com"));
    assert_eq!(db.auth().revoke_all(ann).unwrap(), 1);
    assert_eq!(
        db.auth().validate(&three).unwrap(),
        Validation::Revoked {
            reason: RevokeReason::SignedOutEverywhere
        }
    );
    db.auth()
        .set_standing(ann, Standing::Banned { reason: 7 }, None)
        .unwrap();
    assert_eq!(
        db.auth().standing(ann).unwrap(),
        Some(Standing::Banned { reason: 7 })
    );
    assert!(matches!(
        sign_in(&db, "ann@example.com"),
        SignIn::LockedOut { until: None }
    ));
    assert_eq!(
        db.auth()
            .verify_password("ann@example.com", "wrong")
            .unwrap(),
        Login::Failed
    );
    db.auth().set_standing(ann, Standing::Active, None).unwrap();
    assert!(matches!(
        db.auth().verify_password("ann@example.com", PASSWORD).unwrap(),
        Login::Verified(a) if a == ann
    ));

    // Single-use tokens and identifiers.
    let link = db
        .auth()
        .single_use_token(Purpose::VerifyEmail, ann, Duration::from_secs(60))
        .unwrap();
    assert_eq!(
        db.auth().redeem(&link, Purpose::ResetPassword).unwrap(),
        None
    );
    assert_eq!(
        db.auth().redeem(&link, Purpose::VerifyEmail).unwrap(),
        Some(ann)
    );
    assert_eq!(db.auth().redeem(&link, Purpose::VerifyEmail).unwrap(), None);
    db.auth().add_identifier(ann, "ann2@example.com").unwrap();
    assert!(matches!(
        db.auth()
            .sign_in("ann2@example.com", PASSWORD, SessionSpec::web())
            .unwrap(),
        SignIn::Success { .. }
    ));
    assert!(
        db.auth()
            .single_use_token_for(
                "ann2@example.com",
                Purpose::ResetPassword,
                Duration::from_secs(60)
            )
            .unwrap()
            .is_some()
    );
    assert!(
        db.auth()
            .single_use_token_for(
                "nobody@example.com",
                Purpose::ResetPassword,
                Duration::from_secs(60)
            )
            .unwrap()
            .is_none()
    );
    let new = db.auth().hash_password("a new password").unwrap();
    db.auth().set_password(ann, &new).unwrap();
    assert!(matches!(
        db.auth()
            .sign_in("ann@example.com", "a new password", SessionSpec::web())
            .unwrap(),
        SignIn::Success { .. }
    ));
    // Errors cross the channel as they are.
    assert!(matches!(
        db.auth().create_account("ann@example.com", &new),
        Err(Error::AlreadyExists { what: "identifier" })
    ));
    assert!(matches!(
        db.auth().create_account("", &new),
        Err(Error::Invalid {
            field: "identifier",
            ..
        })
    ));
}

fn test_lock_out_after_failures() {
    let t = TempDir::new("lockout");
    let dir = t.at("db");
    {
        let db = split(&dir);
        db.set_realm_policy(
            "users",
            RealmPolicy::new().lockout(2, Duration::from_secs(600), Duration::from_secs(600)),
        )
        .unwrap();
        let ann = sign_up(&db, "ann@example.com");
        for _ in 0..2 {
            assert_eq!(
                db.auth()
                    .verify_password("ann@example.com", "wrong")
                    .unwrap(),
                Login::Failed
            );
        }
        assert!(matches!(
            db.auth().standing(ann).unwrap(),
            Some(Standing::LockedOut { .. })
        ));
        assert!(matches!(
            sign_in(&db, "ann@example.com"),
            SignIn::LockedOut { until: Some(_) }
        ));
    }
}

fn test_erase_account() {
    let t = TempDir::new("erase");
    let db = split(&t.at("db"));
    let ann = sign_up(&db, "ann@example.com");
    let token = token_of(sign_in(&db, "ann@example.com"));
    let key = db.auth().create_api_key(ann, &["read"], None).unwrap();
    db.auth().erase_account(ann).unwrap();
    assert!(db.auth().account(ann).unwrap().is_none());
    assert_eq!(
        db.auth().validate(&token).unwrap(),
        Validation::Revoked {
            reason: RevokeReason::Erased
        }
    );
    assert!(matches!(sign_in(&db, "ann@example.com"), SignIn::Failed));
    assert_eq!(
        db.auth().validate_api_key(key.as_str()).unwrap(),
        ApiKeyCheck::Unknown
    );
    // The identifier is free again.
    let _ = sign_up(&db, "ann@example.com");
}

fn test_api_keys_recovery_codes_and_roles() {
    let t = TempDir::new("extras");
    let db = split(&t.at("db"));
    let ann = sign_up(&db, "ann@example.com");
    let key = db
        .auth()
        .create_api_key(ann, &["posts:read", "posts:write"], None)
        .unwrap();
    match db.auth().validate_api_key(key.as_str()).unwrap() {
        ApiKeyCheck::Valid {
            account,
            id,
            scopes,
        } => {
            assert_eq!((account, id), (ann, key.id()));
            assert_eq!(scopes, ["posts:read", "posts:write"]);
        }
        other => panic!("{other:?}"),
    }
    assert!(db.auth().revoke_api_key(key.id()).unwrap());
    assert_eq!(
        db.auth().validate_api_key(key.as_str()).unwrap(),
        ApiKeyCheck::Revoked
    );
    assert_eq!(
        db.auth().validate_api_key("short").unwrap(),
        ApiKeyCheck::Malformed
    );

    let codes = db.auth().new_recovery_codes(ann).unwrap();
    let first = codes.codes().next().unwrap().to_owned();
    assert_eq!(codes.codes().count(), 10);
    assert!(db.auth().use_recovery_code(ann, &first).unwrap());
    assert!(!db.auth().use_recovery_code(ann, &first).unwrap());

    let editor = db
        .auth()
        .define_role(Role::new("editor").permission("post.publish"))
        .unwrap();
    assert_eq!(db.auth().role_named("editor"), Some(editor));
    assert!(!db.auth().allowed(ann, "post.publish").unwrap());
    db.auth().assign_roles(ann, &[editor]).unwrap();
    assert_eq!(db.auth().roles(ann).unwrap(), [editor]);
    assert!(db.auth().allowed(ann, "post.publish").unwrap());
    // A role added later is seen: a commit that changes the roles drops
    // what this process kept of them.
    let admin = db.auth().define_role(Role::new("admin")).unwrap();
    assert_eq!(
        db.auth().role(admin).map(|r| r.name().to_owned()),
        Some("admin".to_owned())
    );
    assert!(matches!(
        db.auth().define_role(Role::new("")),
        Err(Error::Invalid { .. })
    ));
    assert_eq!(db.auth().account(ann).unwrap().unwrap().roles(), [editor]);
}

fn test_realms() {
    let t = TempDir::new("realms");
    let dir = t.at("db");
    {
        let db = split(&dir);
        db.define_realm("staff", RealmPolicy::new().pending_verification())
            .unwrap();
        let staff = db.auth_realm("staff").unwrap();
        let hash = staff.hash_password(PASSWORD).unwrap();
        let sam = staff.create_account("sam@example.com", &hash).unwrap();
        assert_eq!(
            staff.standing(sam).unwrap(),
            Some(Standing::PendingVerification)
        );
        assert!(matches!(
            staff
                .sign_in("sam@example.com", PASSWORD, SessionSpec::web())
                .unwrap(),
            SignIn::Success { .. }
        ));
        assert!(matches!(sign_in(&db, "sam@example.com"), SignIn::Failed));
        // One commit across two realms and a space.
        let ann_hash = db.auth().hash_password(PASSWORD).unwrap();
        db.commit(|tx| {
            let _ = tx.auth().create_account("ann@example.com", &ann_hash)?;
            let _ = tx
                .auth_realm("staff")?
                .create_account("ann@example.com", &ann_hash)?;
            let _ = tx.content().create(Entity::new("page").path("/a"))?;
            Ok(())
        })
        .unwrap();
    }
    let db = split(&dir);
    let staff = db.auth_realm("staff").unwrap();
    assert!(matches!(
        staff
            .sign_in("ann@example.com", PASSWORD, SessionSpec::web())
            .unwrap(),
        SignIn::Success { .. }
    ));
    assert!(matches!(
        sign_in(&db, "ann@example.com"),
        SignIn::Success { .. }
    ));
}

fn test_snapshot_reads_and_the_feed() {
    let t = TempDir::new("read");
    let db = split(&t.at("db"));
    let from = db.position();
    let ann = sign_up(&db, "ann@example.com");
    let token = token_of(sign_in(&db, "ann@example.com"));
    let (valid, standing) = db
        .read(|r| Ok((r.auth().validate(&token)?, r.auth().standing(ann)?)))
        .unwrap();
    assert!(valid.session().is_some());
    assert_eq!(standing, Some(Standing::Active));
    // A snapshot sees the standing as of its start.
    db.read(|r| {
        db.auth().set_standing(
            ann,
            Standing::Suspended {
                until: None,
                reason: 1,
            },
            None,
        )?;
        assert_eq!(r.auth().standing(ann)?, Some(Standing::Active));
        // Sessions are read-latest.
        assert!(r.auth().validate(&token)?.session().is_none());
        Ok(())
    })
    .unwrap();
    let changes: Vec<Change> = db
        .feed(from)
        .unwrap()
        .take(3)
        .map(|c| c.unwrap().1)
        .collect();
    assert!(changes.contains(&Change::AccountCreated { account: ann }));
    assert!(changes.contains(&Change::StandingChanged { account: ann }));
}

fn test_a_commit_conflict_runs_again() {
    let t = TempDir::new("conflict");
    let db = split(&t.at("db"));
    let ann = sign_up(&db, "ann@example.com");
    let attempts = AtomicU32::new(0);
    let ended = db
        .commit(|tx| {
            if attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                // A commit in between raises the epoch this one raises.
                let _ = db.auth().revoke_all(ann)?;
            }
            tx.auth().revoke_all(ann)
        })
        .unwrap();
    assert_eq!(ended, 0);
    assert_eq!(attempts.load(Ordering::Relaxed), 2);

    // Serializable: an auth part that only read is checked too.
    let attempts = AtomicU32::new(0);
    db.commit_serializable(|tx| {
        let n = attempts.fetch_add(1, Ordering::Relaxed);
        let unknown = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(!tx.auth().revoke(unknown)?);
        // Reads the account's record, and writes nothing.
        assert!(!tx.auth().remove_identifier(ann, "nobody@example.com")?);
        if n == 0 {
            // Changes what this one read.
            db.auth().set_standing(
                ann,
                Standing::Suspended {
                    until: None,
                    reason: 2,
                },
                None,
            )?;
        }
        tx.content().create(Entity::new("note"))?;
        Ok(())
    })
    .unwrap();
    assert_eq!(attempts.load(Ordering::Relaxed), 2);
}

fn test_password_handles() {
    let t = TempDir::new("handles");
    let a = split(&t.at("a"));
    let b = split(&t.at("b"));
    let from_a = a.auth().hash_password(PASSWORD).unwrap();
    assert_eq!(format!("{from_a:?}"), "HashedPassword(..)");
    assert!(matches!(
        b.auth().create_account("ann@example.com", &from_a),
        Err(Error::Invalid {
            field: "password",
            ..
        })
    ));
    // A handle works for every attempt of a commit, and for later commits.
    let ann = a.auth().create_account("ann@example.com", &from_a).unwrap();
    let bo = a.auth().create_account("bo@example.com", &from_a).unwrap();
    assert_ne!(ann, bo);
    // A hash made by an embedded database is taken whole.
    let e = embedded(&t.at("e"));
    let from_e = e.auth().hash_password(PASSWORD).unwrap();
    let _ = a.auth().create_account("cy@example.com", &from_e).unwrap();
    assert!(matches!(
        sign_in(&a, "cy@example.com"),
        SignIn::Success { .. }
    ));
    // A handle from a split database means nothing to an embedded one.
    assert!(matches!(
        e.auth().create_account("ann@example.com", &from_a),
        Err(Error::Invalid {
            field: "password",
            ..
        })
    ));
}

fn test_backup_and_restore_while_split() {
    let t = TempDir::new("backup");
    let (live, backup, restored) = (t.at("live"), t.at("backup"), t.at("restored"));
    let (ann, token, info) = {
        let db = split(&live);
        let ann = sign_up(&db, "ann@example.com");
        let token = token_of(sign_in(&db, "ann@example.com"));
        db.define_realm("staff", RealmPolicy::new()).unwrap();
        let first = db.backup(&backup).unwrap();
        assert!(!first.incremental() && first.holds_key());
        let _ = sign_up(&db, "bo@example.com");
        let later = db.backup(&backup).unwrap();
        assert!(later.incremental());
        // Taken away after the backup: stays taken away after a restore.
        assert!(db.auth().revoke(&token).unwrap());
        let _ = db.backup(&backup).unwrap();
        (ann, token, later)
    };
    let at = nex_db::restore(&backup, &restored, RestorePoint::Position(info.position())).unwrap();
    assert_eq!(at, info.position());
    let db = split(&restored);
    assert!(db.auth().account(ann).unwrap().is_some());
    assert!(matches!(
        sign_in(&db, "bo@example.com"),
        SignIn::Success { .. }
    ));
    assert!(db.auth().validate(&token).unwrap().session().is_none());
    assert!(db.auth_realm("staff").is_ok());
    drop(db);
    // The restored database opens embedded too.
    let db = embedded(&restored);
    assert!(matches!(
        sign_in(&db, "ann@example.com"),
        SignIn::Success { .. }
    ));
}

fn test_the_application_process_loads_no_key() {
    let t = TempDir::new("keys");
    let key = t.at("key");
    let before = nex_db::root_keys_loaded();
    {
        let db = Database::builder(t.at("db"))
            .keys(Keys::file(&key))
            .auth(AuthMode::separate_process())
            .open()
            .unwrap();
        let ann = sign_up(&db, "ann@example.com");
        let token = token_of(sign_in(&db, "ann@example.com"));
        assert!(db.auth().validate(&token).unwrap().session().is_some());
        db.define_realm("staff", RealmPolicy::new()).unwrap();
        let _ = db.auth().new_recovery_codes(ann).unwrap();
        let _ = db.backup(t.at("backup")).unwrap();
    }
    assert!(key.exists());
    assert_eq!(nex_db::root_keys_loaded(), before);
    // The counter counts: an embedded open loads the key here.
    drop(
        Database::builder(t.at("db"))
            .keys(Keys::file(&key))
            .open()
            .unwrap(),
    );
    assert_eq!(nex_db::root_keys_loaded(), before + 1);
    // The auth process refuses the wrong key, and the database stays
    // closed.
    let other = t.at("other-key");
    assert!(matches!(
        Database::builder(t.at("db"))
            .keys(Keys::file(&other))
            .auth(AuthMode::separate_process())
            .open(),
        Err(Error::KeyUnavailable)
    ));
    assert_eq!(nex_db::root_keys_loaded(), before + 1);
}

fn kill(pid: u32) {
    let status = if cfg!(windows) {
        std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
    } else {
        std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status()
    };
    assert!(status.unwrap().success());
}

/// Run `f` on a thread; panic if it takes longer than `limit`.
fn within<T: Send + 'static>(limit: Duration, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    let _ = std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(limit).expect("hung")
}

fn test_a_killed_auth_process_fails_calls_and_stops_writes() {
    let t = TempDir::new("kill");
    let dir = t.at("db");
    let db = std::sync::Arc::new(split(&dir));
    let ann = sign_up(&db, "ann@example.com");
    let token = token_of(sign_in(&db, "ann@example.com"));
    let rid = db.content().create(Entity::new("page").path("/a")).unwrap();
    kill(db.auth_process_id().unwrap());
    let (d, tk) = (std::sync::Arc::clone(&db), token.as_str().to_owned());
    let validation = within(Duration::from_secs(20), move || {
        // The first call may race the kill: one of the next few fails.
        let mut last = Ok(Validation::Unknown);
        for _ in 0..50 {
            last = d.auth().validate(&tk);
            if last.is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        last
    });
    assert!(matches!(validation, Err(Error::Storage { .. })));
    let d = std::sync::Arc::clone(&db);
    let signed = within(Duration::from_secs(20), move || {
        d.auth()
            .sign_in("ann@example.com", PASSWORD, SessionSpec::web())
    });
    assert!(matches!(signed, Err(Error::Storage { .. })));
    assert!(matches!(db.health(), Health::ReadOnly { .. }));
    // Writes stop, content ones too, as after a failed sync; reads go on.
    assert!(matches!(
        db.content().create(Entity::new("page").path("/b")),
        Err(Error::Storage { .. })
    ));
    assert!(db.content().draft(rid).unwrap().is_some());
    assert!(matches!(db.auth().account(ann), Err(Error::Storage { .. })));
    drop(db);
    // A restart recovers.
    let db = split(&dir);
    assert!(db.auth().validate(&token).unwrap().session().is_some());
    assert!(db.content().draft(rid).unwrap().is_some());
}

fn test_threads_share_the_channel() {
    let t = TempDir::new("threads");
    let db = split(&t.at("db"));
    let _ = sign_up(&db, "ann@example.com");
    let token = token_of(sign_in(&db, "ann@example.com"));
    std::thread::scope(|s| {
        for i in 0..8 {
            let (db, token) = (&db, &token);
            let _ = s.spawn(move || {
                for n in 0..200 {
                    assert!(db.auth().validate(token).unwrap().session().is_some());
                    if n % 50 == 0 {
                        let path = format!("/t{i}/{n}");
                        let _ = db
                            .content()
                            .create(Entity::new("page").path(&path))
                            .unwrap();
                    }
                }
            });
        }
        // A slow hash in the meantime holds no check up.
        let _ = s.spawn(|| db.auth().hash_password(PASSWORD).unwrap());
    });
}

#[cfg(feature = "mfa")]
fn base32_decode(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => panic!("not base32"),
        };
        buffer = (buffer << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    out
}

#[cfg(feature = "mfa")]
fn test_totp_and_passkey_challenges() {
    let t = TempDir::new("mfa");
    let db = split(&t.at("db"));
    let ann = sign_up(&db, "ann@example.com");
    let enrollment = db.auth().add_totp(ann).unwrap();
    let secret = base32_decode(&enrollment.secret());
    let code = |at: u64| format!("{:06}", crypt_io::otp::totp(&secret, at, 6).unwrap());
    let t0 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(db.auth().confirm_totp(ann, &code(t0)).unwrap());
    assert_eq!(
        db.auth()
            .verify_password("ann@example.com", PASSWORD)
            .unwrap(),
        Login::NeedsSecondFactor { account: ann }
    );
    let SignIn::NeedsSecondFactor { challenge } = sign_in(&db, "ann@example.com") else {
        panic!("needs a second factor");
    };
    let SignIn::Success { account, token } = db
        .auth()
        .verify_totp(&challenge, &code(t0 + 30), SessionSpec::web())
        .unwrap()
    else {
        panic!("signed in");
    };
    assert_eq!(account, ann);
    assert!(db.auth().validate(&token).unwrap().session().is_some());
    assert!(db.auth().remove_totp(ann).unwrap());
    // Passkeys: challenges, an empty list, a malformed assertion refused.
    let challenge = db.auth().passkey_registration(ann).unwrap();
    assert_eq!(challenge.as_bytes().len(), 32);
    assert!(db.auth().passkeys(ann).unwrap().is_empty());
    let rp = nex_db::RelyingParty::new("example.com", "https://example.com");
    let _ = db.auth().passkey_sign_in().unwrap();
    assert!(matches!(
        db.auth()
            .verify_passkey(
                &rp,
                &nex_db::PasskeyAssertion::new(b"id", b"{}", b"", b""),
                SessionSpec::web()
            )
            .unwrap(),
        SignIn::Failed
    ));
    assert!(matches!(
        db.auth()
            .add_passkey(ann, &rp, &nex_db::PasskeyRegistration::new(b"{}", b"")),
        Err(Error::Invalid { .. })
    ));
}

fn test_a_decoy_raises_its_event_in_the_application() {
    use std::sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    };
    struct Count(Arc<AtomicU32>);
    impl nex_db::Observer for Count {
        fn on_security_event(&self, event: &nex_db::SecurityEvent) {
            if *event == nex_db::SecurityEvent::DecoyPresented {
                let _ = self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    let dir = TempDir::new("decoy");
    let hits = Arc::new(AtomicU32::new(0));
    let decoy;
    {
        let db = Database::builder(&dir.0)
            .auth(AuthMode::separate_process())
            .observer(Count(Arc::clone(&hits)))
            .open()
            .unwrap();
        decoy = db.auth().plant_decoy().unwrap();
        assert!(matches!(
            db.auth().validate(decoy.as_str()).unwrap(),
            nex_db::Validation::Unknown
        ));
        assert_eq!(hits.load(Ordering::Relaxed), 1);
    }
    // The same decoy, the database opened embedded.
    let db = Database::builder(&dir.0)
        .observer(Count(Arc::clone(&hits)))
        .open()
        .unwrap();
    assert!(matches!(
        db.auth().validate(decoy.as_str()).unwrap(),
        nex_db::Validation::Unknown
    ));
    assert_eq!(hits.load(Ordering::Relaxed), 2);
}

type Test = (&'static str, fn());

const TESTS: &[Test] = &[
    (
        "sign_up_across_engines_reopens_in_either_mode",
        test_sign_up_across_engines_reopens_in_either_mode,
    ),
    (
        "sessions_revoke_and_standing",
        test_sessions_revoke_and_standing,
    ),
    ("lock_out_after_failures", test_lock_out_after_failures),
    ("erase_account", test_erase_account),
    (
        "api_keys_recovery_codes_and_roles",
        test_api_keys_recovery_codes_and_roles,
    ),
    ("realms", test_realms),
    (
        "snapshot_reads_and_the_feed",
        test_snapshot_reads_and_the_feed,
    ),
    (
        "a_commit_conflict_runs_again",
        test_a_commit_conflict_runs_again,
    ),
    ("password_handles", test_password_handles),
    (
        "backup_and_restore_while_split",
        test_backup_and_restore_while_split,
    ),
    (
        "the_application_process_loads_no_key",
        test_the_application_process_loads_no_key,
    ),
    (
        "a_killed_auth_process_fails_calls_and_stops_writes",
        test_a_killed_auth_process_fails_calls_and_stops_writes,
    ),
    ("threads_share_the_channel", test_threads_share_the_channel),
    (
        "a_decoy_raises_its_event_in_the_application",
        test_a_decoy_raises_its_event_in_the_application,
    ),
    #[cfg(feature = "mfa")]
    (
        "totp_and_passkey_challenges",
        test_totp_and_passkey_challenges,
    ),
];

fn main() {
    if nex_db::serve_auth_process().unwrap() {
        return;
    }
    // `cargo test -- name` runs the tests whose names hold `name`.
    let filters: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .collect();
    let mut failed = Vec::new();
    let mut ran = 0;
    for (name, test) in TESTS {
        if !filters.is_empty() && !filters.iter().any(|f| name.contains(f.as_str())) {
            continue;
        }
        ran += 1;
        let started = std::time::Instant::now();
        let outcome = std::panic::catch_unwind(test);
        let took = started.elapsed();
        match outcome {
            Ok(()) => eprintln!("test {name} ... ok ({took:.1?})"),
            Err(_) => {
                eprintln!("test {name} ... FAILED");
                failed.push(*name);
            }
        }
    }
    eprintln!(
        "split: {} passed, {} failed",
        ran - failed.len(),
        failed.len()
    );
    if !failed.is_empty() {
        panic!("failed: {failed:?}");
    }
}
