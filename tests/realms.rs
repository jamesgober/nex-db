//! Named realms and spaces.

use std::{path::PathBuf, time::Duration};

use nex_db::{
    CollectionKind, DEFAULT_SITE, Database, Entity, Error, Locale, PasswordCheck, RealmPolicy,
    SessionSpec, SignIn, SpaceSpec, Standing, Validation,
};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        TempDir(std::env::temp_dir().join(format!(
            "nex-db-realms-{name}-{}-{}",
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

#[test]
fn test_realms_hold_their_own_accounts_sessions_and_policy() {
    let dir = TempDir::new("realms");
    let (staff_token, user_token) = {
        let db = Database::open(&dir.0).unwrap();
        let hour = Duration::from_secs(3600);
        db.define_realm(
            "staff",
            RealmPolicy::new()
                .lockout(2, Duration::from_secs(600), hour)
                .max_session(hour)
                .pending_verification(),
        )
        .unwrap();
        assert!(matches!(
            db.define_realm("staff", RealmPolicy::new()),
            Err(Error::AlreadyExists { .. })
        ));
        assert!(db.define_realm("bad name", RealmPolicy::new()).is_err());
        assert!(db.auth_realm("nobody").is_err());

        let staff = db.auth_realm("staff").unwrap();
        let password = db.auth().hash_password(PASSWORD).unwrap();
        // The same identifier in two realms: two accounts.
        let user = db
            .auth()
            .create_account("ann@example.com", &password)
            .unwrap();
        let admin = staff.create_account("ann@example.com", &password).unwrap();
        assert_ne!(user, admin);
        assert_eq!(
            staff.standing(admin).unwrap(),
            Some(Standing::PendingVerification)
        );
        assert_eq!(db.auth().standing(user).unwrap(), Some(Standing::Active));
        assert_eq!(db.auth().standing(admin).unwrap(), None);

        // A session of one realm is unknown in the other, and the realm's
        // limit cuts a longer one.
        let SignIn::Success { token, .. } = staff
            .sign_in("ann@example.com", PASSWORD, SessionSpec::web())
            .unwrap()
        else {
            panic!("staff sign-in");
        };
        let Validation::Valid(session) = staff.validate(&token).unwrap() else {
            panic!("valid in staff");
        };
        assert!(session.expires_at() <= std::time::SystemTime::now() + Duration::from_secs(3601));
        assert_eq!(db.auth().validate(&token).unwrap(), Validation::Unknown);
        let user_token = db.auth().issue_session(user, SessionSpec::web()).unwrap();
        assert_eq!(staff.validate(&user_token).unwrap(), Validation::Unknown);

        // The staff realm locks out after two failures; the default after ten.
        for _ in 0..2 {
            assert_eq!(
                staff.verify_password("ann@example.com", "wrong").unwrap(),
                PasswordCheck::Failed
            );
        }
        assert!(matches!(
            staff.verify_password("ann@example.com", PASSWORD).unwrap(),
            PasswordCheck::LockedOut { .. }
        ));
        for _ in 0..2 {
            let _ = db.auth().verify_password("ann@example.com", "wrong");
        }
        assert!(matches!(
            db.auth()
                .verify_password("ann@example.com", PASSWORD)
                .unwrap(),
            PasswordCheck::Verified(_)
        ));

        // The default realm's policy can change too.
        db.set_realm_policy("users", RealmPolicy::new().pending_verification())
            .unwrap();
        let later = db
            .auth()
            .create_account("bob@example.com", &password)
            .unwrap();
        assert_eq!(
            db.auth().standing(later).unwrap(),
            Some(Standing::PendingVerification)
        );
        assert!(db.set_realm_policy("nobody", RealmPolicy::new()).is_err());

        // Both realms in one commit.
        db.commit(|tx| {
            let _ = tx.auth().create_account("cy@example.com", &password)?;
            let _ = tx
                .auth_realm("staff")?
                .create_account("cy@example.com", &password)?;
            Ok(())
        })
        .unwrap();
        (token.as_str().to_owned(), user_token.as_str().to_owned())
    };
    // Everything survives a reopen.
    let db = Database::open(&dir.0).unwrap();
    let staff = db.auth_realm("staff").unwrap();
    // The staff lock-out ended that session, and that survives too.
    assert!(matches!(
        staff.validate(&staff_token).unwrap(),
        Validation::Revoked { .. }
    ));
    assert!(matches!(
        db.auth().validate(&user_token).unwrap(),
        Validation::Valid(_)
    ));
    assert_eq!(
        db.auth().validate(&staff_token).unwrap(),
        Validation::Unknown
    );
    let password = db.auth().hash_password(PASSWORD).unwrap();
    let dan = db
        .auth()
        .create_account("dan@example.com", &password)
        .unwrap();
    assert_eq!(
        db.auth().standing(dan).unwrap(),
        Some(Standing::PendingVerification)
    );
    let kinds: Vec<(String, CollectionKind)> = db
        .collections()
        .iter()
        .map(|c| (c.name().to_owned(), c.kind()))
        .collect();
    assert_eq!(
        kinds,
        [
            ("users".to_owned(), CollectionKind::Realm),
            ("site".to_owned(), CollectionKind::Space),
            ("staff".to_owned(), CollectionKind::Realm),
        ]
    );
}

#[test]
fn test_spaces_hold_their_own_content() {
    let dir = TempDir::new("spaces");
    {
        let db = Database::open(&dir.0).unwrap();
        let fr = Locale::new("fr").unwrap();
        db.define_space("blog", SpaceSpec::new(fr)).unwrap();
        let blog = db.content_space("blog").unwrap();
        assert_eq!(blog.space().default_locale(), fr);
        // The same path in two spaces.
        let a = db
            .content()
            .create(Entity::new("page").field("title", "site").path("/x"))
            .unwrap();
        let b = blog
            .create(Entity::new("page").field("title", "blog").path("/x"))
            .unwrap();
        let _ = db.content().publish(a).unwrap();
        let _ = blog.publish(b).unwrap();
        let site_route = db.content().resolve(DEFAULT_SITE, "/x").unwrap().unwrap();
        assert_eq!(site_route.entity(), a);
        let blog_route = blog.resolve(DEFAULT_SITE, "/x").unwrap().unwrap();
        assert_eq!(blog_route.entity(), b);
        assert!(db.content().get(b).unwrap().is_none());
        assert_eq!(blog.get(b).unwrap().unwrap().locale(), fr);
        // In a transaction, by name.
        db.commit(|tx| {
            let _ = tx
                .content_space("blog")?
                .create(Entity::new("page").path("/y"))?;
            Ok(())
        })
        .unwrap();
        // A schedule in a named space fires.
        blog.schedule(b, nex_db::Action::Unpublish, std::time::SystemTime::now())
            .unwrap();
        let mut gone = false;
        for _ in 0..100 {
            if blog.get(b).unwrap().is_none() {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(gone, "the schedule in a named space never fired");
    }
    let db = Database::open(&dir.0).unwrap();
    let blog = db.content_space("blog").unwrap();
    assert!(blog.resolve(DEFAULT_SITE, "/y").unwrap().is_none());
    assert!(blog.resolve(DEFAULT_SITE, "/x").unwrap().is_none());
    assert!(db.content().resolve(DEFAULT_SITE, "/x").unwrap().is_some());
    assert!(db.content_space("nowhere").is_err());
}
