//! Backups taken while the database runs, and point-in-time restores.

use std::path::{Path, PathBuf};

use nex_db::{
    Database, Entity, Error, PasswordCheck, Position, RestorePoint, RevokeReason, SessionSpec,
    Standing, Validation,
};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        TempDir(std::env::temp_dir().join(format!(
            "nex-db-backup-{name}-{}-{}",
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

const PASSWORD: &str = "correct horse battery staple";

fn sign_up(db: &Database, who: &str) -> nex_db::AccountId {
    let hash = db.auth().hash_password(PASSWORD).unwrap();
    db.auth().create_account(who, &hash).unwrap()
}

fn page(db: &Database, path: &str) -> nex_db::EntityId {
    let rid = db
        .content()
        .create(Entity::new("page").field("title", path).path(path))
        .unwrap();
    let _ = db.content().publish(rid).unwrap();
    rid
}

fn resolves(db: &Database, path: &str) -> bool {
    db.content()
        .resolve(nex_db::DEFAULT_SITE, path)
        .unwrap()
        .is_some()
}

fn open(dir: &Path) -> Database {
    Database::open(dir).unwrap()
}

#[test]
fn test_a_full_backup_restores_every_engine() {
    let t = TempDir::new("full");
    let (live, backup, restored) = (t.at("live"), t.at("backup"), t.at("restored"));
    let (ann, token, info) = {
        let db = open(&live);
        let ann = sign_up(&db, "ann@example.com");
        let token = db.auth().issue_session(ann, SessionSpec::web()).unwrap();
        let _ = page(&db, "/home");
        db.define_realm("staff", nex_db::RealmPolicy::new())
            .unwrap();
        let staff = db.auth_realm("staff").unwrap();
        let hash = staff.hash_password(PASSWORD).unwrap();
        let _ = staff.create_account("sam@example.com", &hash).unwrap();
        let info = db.backup(&backup).unwrap();
        assert!(!info.incremental() && info.holds_key());
        assert_eq!(info.base(), info.position());
        // Writes after the backup are not in it.
        let _ = page(&db, "/later");
        (ann, token, info)
    };
    let at = nex_db::restore(&backup, &restored, RestorePoint::Latest).unwrap();
    assert_eq!(at, info.position());
    let db = open(&restored);
    assert!(db.auth().account(ann).unwrap().is_some());
    assert!(matches!(
        db.auth().validate(&token).unwrap(),
        Validation::Valid(_)
    ));
    assert!(resolves(&db, "/home") && !resolves(&db, "/later"));
    assert!(matches!(
        db.auth_realm("staff")
            .unwrap()
            .verify_password("sam@example.com", PASSWORD)
            .unwrap(),
        PasswordCheck::Verified(_)
    ));
    assert!(matches!(
        db.auth()
            .verify_password("ann@example.com", PASSWORD)
            .unwrap(),
        PasswordCheck::Verified(_)
    ));
    // The restored database takes new commits.
    let _ = page(&db, "/after");
    drop(db);
    assert!(resolves(&open(&restored), "/after"));
}

#[test]
fn test_later_backups_add_commits_and_restores_pick_a_point() {
    let t = TempDir::new("points");
    let backup = t.at("backup");
    let (first, middle, last) = {
        let db = open(&t.at("live"));
        let _ = page(&db, "/one");
        let first = db.backup(&backup).unwrap();
        let _ = page(&db, "/two");
        let middle = db.backup(&backup).unwrap();
        assert!(middle.incremental() && middle.base() == first.base());
        let _ = page(&db, "/three");
        let last = db.backup(&backup).unwrap();
        // Nothing new: the same position.
        assert_eq!(db.backup(&backup).unwrap().position(), last.position());
        (first, middle, last)
    };
    // Times that do not depend on the clock's steps: after every commit,
    // and before the backup.
    let later = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
    let cases = [
        (
            "base",
            RestorePoint::Position(first.position()),
            [true, false, false],
        ),
        (
            "middle",
            RestorePoint::Position(middle.position()),
            [true, true, false],
        ),
        ("time", RestorePoint::At(later), [true, true, true]),
        ("latest", RestorePoint::Latest, [true, true, true]),
    ];
    for (name, point, want) in cases {
        let into = t.at(name);
        let _ = nex_db::restore(&backup, &into, point).unwrap();
        let db = open(&into);
        let got = ["/one", "/two", "/three"].map(|p| resolves(&db, p));
        assert_eq!(got, want, "{name}");
    }
    // Points outside the backup, a used directory, and no backup.
    assert!(matches!(
        nex_db::restore(
            &backup,
            t.at("early"),
            RestorePoint::At(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1))
        ),
        Err(Error::Invalid { .. })
    ));
    let outside = Position::from_u64(last.position().get() + 1);
    assert!(matches!(
        nex_db::restore(&backup, t.at("x"), RestorePoint::Position(outside)),
        Err(Error::Invalid { .. })
    ));
    assert!(matches!(
        nex_db::restore(&backup, t.at("latest"), RestorePoint::Latest),
        Err(Error::Invalid { .. })
    ));
    assert!(matches!(
        nex_db::restore(t.at("latest"), t.at("y"), RestorePoint::Latest),
        Err(Error::Invalid { .. })
    ));
    // Another database cannot add to this backup.
    let other = open(&t.at("other"));
    assert!(matches!(other.backup(&backup), Err(Error::Invalid { .. })));
}

#[test]
fn test_revocations_after_the_restore_point_stay() {
    let t = TempDir::new("revocations");
    let backup = t.at("backup");
    let (point, ann, bob, cy, ann_token, bob_token, cy_token) = {
        let db = open(&t.at("live"));
        let ann = sign_up(&db, "ann@example.com");
        let bob = sign_up(&db, "bob@example.com");
        let cy = sign_up(&db, "cy@example.com");
        let ann_token = db.auth().issue_session(ann, SessionSpec::web()).unwrap();
        let bob_token = db.auth().issue_session(bob, SessionSpec::web()).unwrap();
        let cy_token = db.auth().issue_session(cy, SessionSpec::web()).unwrap();
        let point = db.backup(&backup).unwrap().position();
        // After the point: a sign-out, a ban, a password change, an
        // erasure, and an ordinary write.
        assert!(db.auth().revoke(&ann_token).unwrap());
        db.auth()
            .set_standing(bob, Standing::Banned { reason: 7 }, None)
            .unwrap();
        let new = db.auth().hash_password("a new password").unwrap();
        db.auth().set_password(cy, &new).unwrap();
        let _ = page(&db, "/later");
        let dan = sign_up(&db, "dan@example.com");
        db.auth().erase_account(dan).unwrap();
        let _ = db.backup(&backup).unwrap();
        (point, ann, bob, cy, ann_token, bob_token, cy_token)
    };
    let into = t.at("restored");
    assert_eq!(
        nex_db::restore(&backup, &into, RestorePoint::Position(point)).unwrap(),
        point
    );
    for _ in 0..2 {
        // Applied once; a second open finds nothing more to apply.
        let db = open(&into);
        assert!(!resolves(&db, "/later"));
        assert_eq!(
            db.auth().validate(&ann_token).unwrap(),
            Validation::Revoked {
                reason: RevokeReason::Revoked
            }
        );
        assert!(!matches!(
            db.auth().validate(&bob_token).unwrap(),
            Validation::Valid(_)
        ));
        assert_eq!(
            db.auth().standing(bob).unwrap(),
            Some(Standing::Banned { reason: 7 })
        );
        // The old password no longer works, and its sessions ended.
        assert_eq!(
            db.auth()
                .verify_password("cy@example.com", PASSWORD)
                .unwrap(),
            PasswordCheck::Failed
        );
        assert!(matches!(
            db.auth()
                .verify_password("cy@example.com", "a new password")
                .unwrap(),
            PasswordCheck::Verified(a) if a == cy
        ));
        assert!(!matches!(
            db.auth().validate(&cy_token).unwrap(),
            Validation::Valid(_)
        ));
        assert!(db.auth().account(ann).unwrap().is_some());
    }
}
