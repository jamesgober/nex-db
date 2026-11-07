//! The change feed.

use std::{path::PathBuf, time::Duration};

use nex_db::{Change, DEFAULT_SITE, Database, Entity, Error, SessionSpec, Standing};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        TempDir(std::env::temp_dir().join(format!(
            "nex-db-feed-{name}-{}-{}",
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

fn drain(feed: &mut nex_db::Feed<'_>) -> Vec<Change> {
    let mut out = Vec::new();
    while let Some((_, change)) = feed.try_next().unwrap() {
        out.push(change);
    }
    out
}

#[test]
fn test_the_feed_reports_content_and_auth_changes_in_order() {
    let dir = TempDir::new("order");
    let db = Database::open(&dir.0).unwrap();
    let start = db.position();
    let mut feed = db.feed(start).unwrap();
    assert!(feed.try_next().unwrap().is_none());

    let password = db.auth().hash_password("a long password").unwrap();
    let ann = db
        .auth()
        .create_account("ann@example.com", &password)
        .unwrap();
    let token = db.auth().issue_session(ann, SessionSpec::web()).unwrap();
    let rid = db
        .commit(|tx| {
            let rid = tx.content().create(Entity::new("page").path("/p"))?;
            let _ = tx.content().publish(rid)?;
            Ok(rid)
        })
        .unwrap();
    assert!(db.auth().revoke(&token).unwrap());
    db.auth()
        .set_standing(
            ann,
            Standing::Suspended {
                until: None,
                reason: 1,
            },
            None,
        )
        .unwrap();

    let changes = drain(&mut feed);
    assert_eq!(changes[0], Change::AccountCreated { account: ann });
    assert!(changes.contains(&Change::EntityChanged { rid, revision: 1 }));
    assert!(changes.contains(&Change::RouteChanged {
        site: DEFAULT_SITE.to_owned(),
        path: "/p".to_owned()
    }));
    assert!(changes.contains(&Change::SessionRevoked { account: Some(ann) }));
    assert!(changes.contains(&Change::StandingChanged { account: ann }));
    // Issuing a session is not reported.
    assert_eq!(changes.len(), 6, "{changes:?}");

    // A feed from a later position sees only later changes.
    let mut later = db.feed(db.position()).unwrap();
    let _ = db.content().unpublish(rid).unwrap();
    assert_eq!(
        drain(&mut later),
        [
            Change::EntityChanged { rid, revision: 0 },
            Change::RouteChanged {
                site: DEFAULT_SITE.to_owned(),
                path: "/p".to_owned()
            }
        ]
    );
}

#[test]
fn test_a_waiting_reader_gets_the_next_commit() {
    let dir = TempDir::new("wait");
    let db = Database::open(&dir.0).unwrap();
    let mut feed = db.feed(db.position()).unwrap();
    assert!(
        feed.next_timeout(Duration::from_millis(20))
            .unwrap()
            .is_none()
    );
    let got = std::thread::scope(|s| {
        let reader = s.spawn(move || feed.next_timeout(Duration::from_secs(20)).unwrap());
        std::thread::sleep(Duration::from_millis(50));
        let _ = db.content().create(Entity::new("note")).unwrap();
        reader.join().unwrap()
    });
    assert!(matches!(
        got,
        Some((_, Change::EntityChanged { revision: 0, .. }))
    ));
}

#[test]
fn test_a_position_from_before_the_open_is_behind() {
    let dir = TempDir::new("behind");
    let old = {
        let db = Database::open(&dir.0).unwrap();
        let old = db.position();
        let _ = db.content().create(Entity::new("note")).unwrap();
        old
    };
    let db = Database::open(&dir.0).unwrap();
    assert!(matches!(db.feed(old), Err(Error::FeedBehind { .. })));
    assert!(db.feed(db.position()).is_ok());
    assert_eq!(Error::FeedBehind { oldest: 1 }.code(), "NEX-1012");
}
