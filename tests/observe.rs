//! Health and observers.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use nex_db::{CommitInfo, Database, Entity, Error, Health, Observer, SecurityEvent, SessionSpec};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        TempDir(std::env::temp_dir().join(format!(
            "nex-db-observe-{name}-{}-{}",
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

#[derive(Default)]
struct Seen {
    commits: Vec<CommitInfo>,
    errors: Vec<String>,
    events: Vec<SecurityEvent>,
}

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Seen>>);

impl Observer for Recorder {
    fn on_commit(&self, commit: &CommitInfo) {
        self.0.lock().unwrap().commits.push(*commit);
    }

    fn on_error(&self, error: &Error) {
        self.0.lock().unwrap().errors.push(error.code().to_owned());
    }

    fn on_security_event(&self, event: &SecurityEvent) {
        self.0.lock().unwrap().events.push(*event);
    }
}

#[test]
fn test_observer_hears_commits_errors_and_security_events() {
    let dir = TempDir::new("observer");
    let seen = Recorder::default();
    let db = Database::builder(&dir.0)
        .observer(seen.clone())
        .open()
        .unwrap();
    assert_eq!(db.health(), Health::Ready);

    let password = db.auth().hash_password("a long password").unwrap();
    let ann = db
        .auth()
        .create_account("ann@example.com", &password)
        .unwrap();
    let rid = db.content().create(Entity::new("page").path("/x")).unwrap();
    let _ = db.content().publish(rid).unwrap();
    assert!(db.content().create(Entity::new("page").path("/x")).is_err());

    let _ = db
        .auth()
        .verify_password("ann@example.com", "wrong password")
        .unwrap();
    let _ = db
        .auth()
        .verify_password("nobody@example.com", "wrong password")
        .unwrap();
    let token = db.auth().issue_session(ann, SessionSpec::web()).unwrap();
    assert!(db.auth().revoke(&token).unwrap());
    let _ = db.auth().validate(&token).unwrap();

    let seen = seen.0.lock().unwrap();
    // create account, create, publish, issue, revoke.
    assert_eq!(seen.commits.len(), 5);
    assert!(
        seen.commits
            .windows(2)
            .all(|w| w[0].position() < w[1].position())
    );
    assert!(seen.commits.iter().all(|c| c.attempts() == 1));
    assert_eq!(seen.errors, ["NEX-1001"]);
    assert_eq!(
        seen.events,
        [
            SecurityEvent::SignInFailed { account: Some(ann) },
            SecurityEvent::SignInFailed { account: None },
            SecurityEvent::RevokedSessionPresented,
        ]
    );
}

#[test]
fn test_repeated_failures_report_the_lock_out() {
    let dir = TempDir::new("lockout");
    let seen = Recorder::default();
    let db = Database::builder(&dir.0)
        .observer(seen.clone())
        .open()
        .unwrap();
    let password = db.auth().hash_password("a long password").unwrap();
    let ann = db
        .auth()
        .create_account("ann@example.com", &password)
        .unwrap();
    for _ in 0..10 {
        let _ = db
            .auth()
            .verify_password("ann@example.com", "wrong password")
            .unwrap();
    }
    let _ = db
        .auth()
        .verify_password("ann@example.com", "a long password")
        .unwrap();
    let events = seen.0.lock().unwrap().events.clone();
    assert!(events.contains(&SecurityEvent::LockedOut { account: ann }));
    assert_eq!(events.last(), Some(&SecurityEvent::SignInBlocked));
}
