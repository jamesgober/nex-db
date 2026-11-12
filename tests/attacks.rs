//! Attacks that must fail: what a stolen disk, a timing probe, a guessing
//! attacker, or an application bug can get out of the database.
//!
//! Each test states the attack and what stops it. Other attacks are tested
//! where the defence lives: tampered log and checkpoint bytes (`recovery`),
//! the audit chain, sealed-section sizes, revocations on every path
//! (`commit`, `backup`, `split`), erasure (`erasure`), and realms (`realms`).

use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use nex_db::{Database, Keys, SessionSpec, SignIn, Validation};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        TempDir(std::env::temp_dir().join(format!(
            "nex-db-attacks-{name}-{}-{}",
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
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files_under(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// A stolen disk or backup without the key: no file holds an identifier,
/// a password, or a session token (or its random part in base64). The key
/// lives outside the directory here, as in production.
#[test]
fn test_files_without_the_key_hold_no_identifier_password_or_token() {
    let dir = TempDir::new("disk");
    let key_dir = TempDir::new("key");
    std::fs::create_dir_all(&key_dir.0).unwrap();
    let identifier = "alice.secret.identifier@example.com";
    let password = "correct horse battery staple 9417";
    let token_text;
    {
        let db = Database::builder(&dir.0)
            .keys(Keys::file(key_dir.0.join("root.key")))
            .open()
            .unwrap();
        let hashed = db.auth().hash_password(password).unwrap();
        let account = db.auth().create_account(identifier, &hashed).unwrap();
        let token = db
            .auth()
            .issue_session(account, SessionSpec::web())
            .unwrap();
        token_text = token.as_str().to_owned();
        // A failed sign-in and a sign-in, so counters and sessions are
        // written too.
        assert!(matches!(
            db.auth()
                .sign_in(identifier, "wrong password", SessionSpec::web())
                .unwrap(),
            SignIn::Failed
        ));
        assert!(matches!(
            db.auth()
                .sign_in(identifier, password, SessionSpec::web())
                .unwrap(),
            SignIn::Success { .. }
        ));
        let backup = dir.0.with_extension("backup");
        let _ = db.backup(&backup).unwrap();
        // The directory and the backup both count as the stolen disk.
        let mut files = Vec::new();
        files_under(&backup, &mut files);
        assert!(!files.is_empty());
        for file in &files {
            let bytes = std::fs::read(file).unwrap();
            assert!(!contains(&bytes, identifier.as_bytes()), "{file:?}");
            assert!(!contains(&bytes, password.as_bytes()), "{file:?}");
            assert!(!contains(&bytes, token_text.as_bytes()), "{file:?}");
        }
        let _ = std::fs::remove_dir_all(&backup);
    }
    let mut files = Vec::new();
    files_under(&dir.0, &mut files);
    assert!(files.len() > 3);
    for file in &files {
        let bytes = std::fs::read(file).unwrap();
        assert!(!contains(&bytes, identifier.as_bytes()), "{file:?}");
        assert!(!contains(&bytes, password.as_bytes()), "{file:?}");
        assert!(!contains(&bytes, token_text.as_bytes()), "{file:?}");
        // The random part of a token is its last 44 characters.
        assert!(!contains(&bytes, &token_text.as_bytes()[4..]), "{file:?}");
    }
    // And without the key the database does not open.
    std::fs::remove_file(key_dir.0.join("root.key")).unwrap();
    assert!(
        Database::builder(&dir.0)
            .keys(Keys::file(key_dir.0.join("root.key")))
            .open()
            .is_err()
    );
}

/// No call hands out a password hash, not even through `Debug`.
#[test]
fn test_no_call_shows_a_password_hash() {
    let dir = TempDir::new("hash");
    let db = Database::open(&dir.0).unwrap();
    let hashed = db.auth().hash_password("a password to hide").unwrap();
    let shown = format!("{hashed:?}");
    assert!(!shown.contains("argon2"), "{shown}");
    assert!(!shown.contains('$'), "{shown}");
    let account = db
        .auth()
        .create_account("hash@example.com", &hashed)
        .unwrap();
    let view = format!("{:?}", db.auth().account(account).unwrap());
    assert!(!view.contains("argon2"), "{view}");
    assert!(!view.contains("hash@example.com"), "{view}");
}

/// Account enumeration by timing: a wrong password for an identifier that
/// exists costs the same Argon2id hash as an identifier that does not.
#[test]
fn test_known_and_unknown_identifiers_take_the_same_time() {
    let dir = TempDir::new("timing");
    let db = Database::open(&dir.0).unwrap();
    let hashed = db.auth().hash_password("the right password").unwrap();
    let _ = db
        .auth()
        .create_account("known@example.com", &hashed)
        .unwrap();
    let time = |identifier: &str| {
        let started = Instant::now();
        let outcome = db
            .auth()
            .sign_in(identifier, "a wrong password", SessionSpec::web())
            .unwrap();
        assert!(matches!(outcome, SignIn::Failed));
        started.elapsed()
    };
    // Warm both paths (the first unknown identifier builds the dummy hash).
    let _ = time("known@example.com");
    let _ = time("nobody@example.com");
    let mut known = Vec::new();
    let mut unknown = Vec::new();
    for i in 0..5 {
        known.push(time("known@example.com"));
        unknown.push(time(&format!("nobody{i}@example.com")));
    }
    known.sort();
    unknown.sort();
    let (k, u) = (known[2], unknown[2]);
    // Both are one Argon2id hash (tens of milliseconds); a missing hash on
    // either side would differ by a factor of a hundred.
    assert!(k > Duration::from_millis(2) && u > Duration::from_millis(2));
    let ratio = k.as_secs_f64() / u.as_secs_f64();
    assert!((0.33..3.0).contains(&ratio), "known {k:?}, unknown {u:?}");
}

/// Credential stuffing: repeated failures lock the account, and the lock
/// survives a restart (the counter is durable).
#[test]
fn test_a_lock_out_survives_a_restart() {
    let dir = TempDir::new("lockout");
    {
        let db = Database::open(&dir.0).unwrap();
        let hashed = db.auth().hash_password("the right password").unwrap();
        let _ = db
            .auth()
            .create_account("stuffed@example.com", &hashed)
            .unwrap();
        for _ in 0..20 {
            let _ = db
                .auth()
                .sign_in("stuffed@example.com", "guess", SessionSpec::web())
                .unwrap();
        }
    }
    let db = Database::open(&dir.0).unwrap();
    assert!(matches!(
        db.auth()
            .sign_in(
                "stuffed@example.com",
                "the right password",
                SessionSpec::web()
            )
            .unwrap(),
        SignIn::LockedOut { .. }
    ));
}

/// Guessed tokens: a well-formed token that was never issued is `Unknown`,
/// and a malformed one is `Malformed`, whatever its shape.
#[test]
fn test_guessed_tokens_are_never_accepted() {
    let dir = TempDir::new("guess");
    let db = Database::open(&dir.0).unwrap();
    let hashed = db.auth().hash_password("pw for guessing").unwrap();
    let account = db
        .auth()
        .create_account("guess@example.com", &hashed)
        .unwrap();
    let real = db
        .auth()
        .issue_session(account, SessionSpec::web())
        .unwrap();
    let text = real.as_str().to_owned();
    // The same token with one character changed. Characters 5 on carry
    // the random part: any change is a token never issued. Characters 1 to
    // 4 carry only the routing prefix, which is never trusted and names no
    // session, so the session is the same one.
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let changed = |i: usize| {
        let mut bytes = text.clone().into_bytes();
        let c = bytes[i];
        bytes[i] = alphabet[(alphabet.iter().position(|a| *a == c).unwrap() + 1) % 64];
        String::from_utf8(bytes).unwrap()
    };
    for i in 5..text.len() {
        assert!(
            matches!(db.auth().validate(changed(i)).unwrap(), Validation::Unknown),
            "position {i}"
        );
    }
    for i in 1..5 {
        match db.auth().validate(changed(i)).unwrap() {
            Validation::Valid(s) => assert_eq!(s.account(), account, "position {i}"),
            other => panic!("position {i}: {other:?}"),
        }
    }
    for junk in ["", "x", &"A".repeat(48), &format!("{text}A"), &text[1..]] {
        assert!(!matches!(
            db.auth().validate(junk).unwrap(),
            Validation::Valid(_)
        ));
    }
    assert!(matches!(
        db.auth().validate(&text).unwrap(),
        Validation::Valid(_)
    ));
}

/// An application bug cannot read auth data through content: the content
/// engine's code never names the auth engine, and the auth engine's never
/// names content. Checked on the source, so a change that adds such a path
/// fails here.
#[test]
fn test_engines_never_reach_each_other() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let check = |dir: &str, forbidden: &[&str]| {
        let mut files = Vec::new();
        files_under(&root.join(dir), &mut files);
        assert!(!files.is_empty());
        for file in files {
            let text = std::fs::read_to_string(&file).unwrap();
            for word in forbidden {
                assert!(!text.contains(word), "{file:?} names {word}");
            }
        }
    };
    check("content", &["crate::auth", "super::auth", "AuthEngine"]);
    check("auth", &["crate::content", "ContentEngine"]);
}

/// Counts decoy events.
struct Decoys(std::sync::Arc<std::sync::atomic::AtomicU32>);

impl nex_db::Observer for Decoys {
    fn on_security_event(&self, event: &nex_db::SecurityEvent) {
        if *event == nex_db::SecurityEvent::DecoyPresented {
            let _ = self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Probing with a stolen or planted token: a decoy is answered `Unknown`,
/// as any token never issued, and raises an event. It survives a restart
/// (from the log, and from the checkpoint written at close), is never
/// listed as a session, and `revoke` retires it (then it raises nothing).
#[test]
fn test_a_decoy_answers_unknown_and_raises_an_event() {
    use std::sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    };
    let dir = TempDir::new("decoy");
    let hits = Arc::new(AtomicU32::new(0));
    let open = || {
        Database::builder(&dir.0)
            .observer(Decoys(Arc::clone(&hits)))
            .open()
            .unwrap()
    };
    let decoy;
    {
        let db = open();
        let hashed = db.auth().hash_password("pw for decoys").unwrap();
        let account = db
            .auth()
            .create_account("decoy@example.com", &hashed)
            .unwrap();
        let _ = db
            .auth()
            .issue_session(account, SessionSpec::web())
            .unwrap();
        decoy = db.auth().plant_decoy().unwrap();
        assert_eq!(decoy.as_str().len(), 48);
        assert!(matches!(
            db.auth().validate(decoy.as_str()).unwrap(),
            Validation::Unknown
        ));
        assert_eq!(hits.load(Ordering::Relaxed), 1);
        // A token never issued raises nothing.
        let other = format!("AQAA{}", "B".repeat(44));
        assert!(matches!(
            db.auth().validate(&other).unwrap(),
            Validation::Unknown
        ));
        assert_eq!(hits.load(Ordering::Relaxed), 1);
        // At a snapshot too.
        let seen = db.read(|r| r.auth().validate(decoy.as_str())).unwrap();
        assert!(matches!(seen, Validation::Unknown));
        assert_eq!(hits.load(Ordering::Relaxed), 2);
        // Not a session of anyone.
        assert_eq!(db.auth().sessions(account).unwrap().len(), 1);
    }
    let db = open();
    assert!(matches!(
        db.auth().validate(decoy.as_str()).unwrap(),
        Validation::Unknown
    ));
    assert_eq!(hits.load(Ordering::Relaxed), 3);
    // Since 0.8 `revoke` raises the alarm too and leaves the decoy planted;
    // `retire_decoy` removes it.
    assert!(!db.auth().revoke(&decoy).unwrap());
    assert_eq!(hits.load(Ordering::Relaxed), 4);
    assert!(db.auth().retire_decoy(&decoy).unwrap());
    assert!(matches!(
        db.auth().validate(decoy.as_str()).unwrap(),
        Validation::Unknown
    ));
    assert_eq!(hits.load(Ordering::Relaxed), 4);
    drop(db);
    let db = open();
    assert!(matches!(
        db.auth().validate(decoy.as_str()).unwrap(),
        Validation::Unknown
    ));
    assert_eq!(
        hits.load(Ordering::Relaxed),
        4,
        "a retired decoy stays gone"
    );
}
