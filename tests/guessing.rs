//! Guessing defences: a lock-out answers alike for every password and checks
//! none, it commits nothing and ends no session, second-factor checks count
//! toward it, and a decoy raises the alarm wherever it is presented.

#![cfg(feature = "auth")]

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use nex_db::{Database, Observer, PasswordCheck, SecurityEvent, SessionSpec, SignIn, Validation};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        TempDir(std::env::temp_dir().join(format!(
            "nex-db-guessing-{name}-{}-{}",
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

const PASSWORD: &str = "correct horse battery staple";

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<SecurityEvent>>>);

impl Observer for Events {
    fn on_security_event(&self, event: &SecurityEvent) {
        self.0.lock().unwrap().push(*event);
    }
}

impl Events {
    fn decoys(&self) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|e| matches!(e, SecurityEvent::DecoyPresented))
            .count()
    }
}

/// Before 0.8 the right password answered `LockedOut` and a wrong one
/// `Failed`, so guessing went on at full speed and the different answer named
/// the password. Now every password answers the same while locked out.
#[test]
fn test_a_lock_out_answers_alike_for_every_password() {
    let t = TempDir::new("alike");
    let db = Database::open(&t.0).unwrap();
    let _ = db.auth().sign_up("ann@example.com", PASSWORD).unwrap();
    for _ in 0..10 {
        let _ = db
            .auth()
            .verify_password("ann@example.com", "wrong")
            .unwrap();
    }
    let right = db
        .auth()
        .verify_password("ann@example.com", PASSWORD)
        .unwrap();
    let wrong = db
        .auth()
        .verify_password("ann@example.com", "wrong")
        .unwrap();
    assert!(matches!(right, PasswordCheck::LockedOut { until: Some(_) }));
    assert_eq!(right, wrong);
    assert!(matches!(
        db.auth()
            .sign_in("ann@example.com", PASSWORD, SessionSpec::web())
            .unwrap(),
        SignIn::LockedOut { .. }
    ));
}

/// The failure that locks out commits nothing (before 0.8 it committed a
/// standing change, a durable write only a real account paid for, and ended
/// every session of the account).
#[test]
fn test_a_lock_out_commits_nothing_and_ends_no_session() {
    let t = TempDir::new("nothing");
    let db = Database::open(&t.0).unwrap();
    let ann = db.auth().sign_up("ann@example.com", PASSWORD).unwrap();
    let token = db.auth().issue_session(ann, SessionSpec::web()).unwrap();
    let before = db.position();
    for _ in 0..12 {
        let _ = db
            .auth()
            .verify_password("ann@example.com", "wrong")
            .unwrap();
    }
    assert_eq!(db.position(), before, "a failed sign-in commits nothing");
    assert!(matches!(
        db.auth().validate(&token).unwrap(),
        Validation::Valid(_)
    ));
}

/// Before 0.8 `check_totp` counted no failure: 200 wrong codes, then the
/// right one was accepted. Now ten wrong codes lock the account out, the
/// lock-out is shared with its passwords, and no code is checked meanwhile.
#[cfg(feature = "mfa")]
#[test]
fn test_check_totp_counts_failures_and_shares_the_lock_out() {
    let t = TempDir::new("totp");
    let db = Database::open(&t.0).unwrap();
    let ann = db.auth().sign_up("ann@example.com", PASSWORD).unwrap();
    let enrollment = db.auth().add_totp(ann).unwrap();
    let secret = base32_decode(&enrollment.secret());
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    let code = |at: u64| format!("{:06}", crypt_io::otp::totp(&secret, at, 6).unwrap());
    assert!(db.auth().confirm_totp(ann, &code(now())).unwrap());
    let wrong = if code(now()) == "000000" {
        "111111"
    } else {
        "000000"
    };
    for _ in 0..10 {
        assert!(!db.auth().check_totp(ann, wrong).unwrap());
    }
    // Locked out: even the right code is refused, and so is the password.
    assert!(!db.auth().check_totp(ann, &code(now() + 30)).unwrap());
    assert!(matches!(
        db.auth()
            .verify_password("ann@example.com", PASSWORD)
            .unwrap(),
        PasswordCheck::LockedOut { .. }
    ));
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

/// Before 0.8 a decoy sent to `revoke` (a logout handler) answered `true`,
/// raised nothing, and was gone. Now `revoke`, `rotate`, and `redeem` raise
/// `DecoyPresented`, answer as for a token never issued, and leave it
/// planted; `retire_decoy` removes it.
#[test]
fn test_a_decoy_raises_the_alarm_wherever_it_is_presented() {
    let t = TempDir::new("decoy");
    let events = Events::default();
    let db = Database::builder(&t.0)
        .observer(events.clone())
        .open()
        .unwrap();
    let decoy = db.auth().plant_decoy().unwrap();
    assert!(!db.auth().revoke(&decoy).unwrap());
    assert_eq!(events.decoys(), 1);
    assert!(db.auth().rotate(&decoy).is_err());
    assert_eq!(events.decoys(), 2);
    assert_eq!(
        db.auth()
            .redeem(&decoy, nex_db::Purpose::VerifyEmail)
            .unwrap(),
        None
    );
    assert_eq!(events.decoys(), 3);
    // Still planted after all of that.
    assert_eq!(db.auth().validate(&decoy).unwrap(), Validation::Unknown);
    assert_eq!(events.decoys(), 4);
    assert!(db.auth().retire_decoy(&decoy).unwrap());
    assert_eq!(db.auth().validate(&decoy).unwrap(), Validation::Unknown);
    assert_eq!(
        events.decoys(),
        4,
        "a retired decoy is just an unknown token"
    );
    assert!(!db.auth().retire_decoy(&decoy).unwrap());
}
