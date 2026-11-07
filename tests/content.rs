//! Drafts, revisions, publishing, and routes.

use std::path::PathBuf;

use nex_db::{
    Cursor, DEFAULT_SITE, Database, Entity, Error, Listing, Patch, RouteKind, Status, Value,
    Visibility,
};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        TempDir(std::env::temp_dir().join(format!(
            "nex-db-content-{name}-{}-{}",
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

fn title(db: &Database, rid: nex_db::Rid) -> Option<String> {
    db.content()
        .get(rid)
        .unwrap()
        .and_then(|e| e.field("title").and_then(Value::as_text).map(str::to_owned))
}

#[test]
fn test_draft_publish_edit_republish_and_unpublish() {
    let dir = TempDir::new("lifecycle");
    let db = Database::open(&dir.0).unwrap();
    let rid = db
        .content()
        .create(Entity::new("post").field("title", "One").path("/one"))
        .unwrap();
    let draft = db.content().draft(rid).unwrap().unwrap();
    assert_eq!(draft.status(), Status::Draft);
    assert_eq!(draft.revision(), 0);
    assert!(db.content().get(rid).unwrap().is_none());
    assert!(
        db.content()
            .resolve(DEFAULT_SITE, "/one")
            .unwrap()
            .is_none()
    );

    assert_eq!(db.content().publish(rid).unwrap(), 1);
    // Publishing an unchanged draft again makes no new revision.
    assert_eq!(db.content().publish(rid).unwrap(), 1);
    let route = db.content().resolve(DEFAULT_SITE, "/one").unwrap().unwrap();
    assert_eq!((route.entity(), route.revision()), (rid, 1));
    let entry = db.content().get(rid).unwrap().unwrap();
    assert_eq!(entry.status(), Status::Published);
    assert!(entry.published_at().is_some());
    let first = entry.first_published_at();

    db.content()
        .save_draft(rid, Patch::new().set("title", "Two"))
        .unwrap();
    assert_eq!(title(&db, rid).as_deref(), Some("One"));
    assert_eq!(db.content().save_revision(rid, "edited").unwrap(), 2);
    assert_eq!(title(&db, rid).as_deref(), Some("One"));
    assert_eq!(db.content().publish(rid).unwrap(), 2);
    assert_eq!(title(&db, rid).as_deref(), Some("Two"));
    let entry = db.content().get(rid).unwrap().unwrap();
    assert_eq!(entry.first_published_at(), first);
    let revisions = db.content().revisions(rid).unwrap();
    assert_eq!(
        revisions
            .iter()
            .map(|r| (r.number(), r.message().to_owned()))
            .collect::<Vec<_>>(),
        [(1, String::new()), (2, "edited".to_owned())]
    );
    let old = db.content().revision(rid, 1).unwrap().unwrap();
    assert_eq!(old.field("title").and_then(Value::as_text), Some("One"));

    assert!(db.content().unpublish(rid).unwrap());
    assert!(!db.content().unpublish(rid).unwrap());
    assert!(db.content().get(rid).unwrap().is_none());
    assert!(
        db.content()
            .resolve(DEFAULT_SITE, "/one")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        db.content().draft(rid).unwrap().unwrap().status(),
        Status::Draft
    );
}

#[test]
fn test_moving_a_page_leaves_a_redirect() {
    let dir = TempDir::new("moves");
    let db = Database::open(&dir.0).unwrap();
    let rid = db.content().create(Entity::new("page").path("/a")).unwrap();
    let _ = db.content().publish(rid).unwrap();
    db.content().set_path(rid, "/b").unwrap();
    db.content().set_path(rid, "/c").unwrap();
    let moved = RouteKind::Redirect {
        to: rid,
        status: 301,
    };
    for old in ["/a", "/b"] {
        let route = db.content().resolve(DEFAULT_SITE, old).unwrap().unwrap();
        assert_eq!(route.kind(), moved);
    }
    let route = db.content().resolve(DEFAULT_SITE, "/c").unwrap().unwrap();
    assert_eq!(route.kind(), RouteKind::Page);
    assert_eq!(
        db.content().get(rid).unwrap().unwrap().route(),
        Some((DEFAULT_SITE, "/c"))
    );

    // Another entity may take a path that only redirects.
    let other = db.content().create(Entity::new("page").path("/a")).unwrap();
    let _ = db.content().publish(other).unwrap();
    let at_a = db.content().resolve(DEFAULT_SITE, "/a").unwrap().unwrap();
    assert_eq!((at_a.entity(), at_a.kind()), (other, RouteKind::Page));
    // But not one that serves a page.
    assert!(matches!(
        db.content().set_path(other, "/c"),
        Err(Error::AlreadyExists { what: "path" })
    ));

    // Moving the draft's path and publishing moves the page too.
    db.content()
        .save_draft(rid, Patch::new().path("/d"))
        .unwrap();
    let _ = db.content().publish(rid).unwrap();
    let at_c = db.content().resolve(DEFAULT_SITE, "/c").unwrap().unwrap();
    assert_eq!(at_c.kind(), moved);
}

#[test]
fn test_status_and_visibility_rules() {
    let dir = TempDir::new("status");
    let db = Database::open(&dir.0).unwrap();
    let rid = db
        .content()
        .create(Entity::new("page").path("/members"))
        .unwrap();
    db.commit(|tx| tx.content().set_status(rid, Status::Review))
        .unwrap();
    assert_eq!(
        db.content().draft(rid).unwrap().unwrap().status(),
        Status::Review
    );
    assert!(
        db.commit(|tx| tx.content().set_status(rid, Status::Published))
            .is_err()
    );
    let _ = db.content().publish(rid).unwrap();
    assert!(
        db.commit(|tx| tx.content().set_status(rid, Status::Draft))
            .is_err()
    );
    db.commit(|tx| tx.content().set_visibility(rid, Visibility::Members))
        .unwrap();
    let route = db
        .content()
        .resolve(DEFAULT_SITE, "/members")
        .unwrap()
        .unwrap();
    assert_eq!(route.visibility(), Visibility::Members);
    db.commit(|tx| tx.content().set_status(rid, Status::Archived))
        .unwrap();
    assert!(
        db.content()
            .resolve(DEFAULT_SITE, "/members")
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        db.content()
            .save_draft(nex_db::Rid::from_bytes([1; 16]), Patch::new()),
        Err(Error::Invalid { .. })
    ));
}

#[test]
fn test_routes_drafts_and_revisions_survive_a_reopen() {
    let dir = TempDir::new("reopen");
    let (moved, draft, gone) = {
        let db = Database::open(&dir.0).unwrap();
        let moved = db
            .content()
            .create(Entity::new("page").field("title", "M").path("/old"))
            .unwrap();
        let _ = db.content().publish(moved).unwrap();
        db.content().set_path(moved, "/new").unwrap();
        let draft = db
            .content()
            .create(Entity::new("page").field("title", "D").path("/draft"))
            .unwrap();
        let gone = db
            .content()
            .create(Entity::new("page").path("/gone"))
            .unwrap();
        let _ = db.content().publish(gone).unwrap();
        let _ = db.content().unpublish(gone).unwrap();
        (moved, draft, gone)
    };
    let db = Database::open(&dir.0).unwrap();
    let old = db.content().resolve(DEFAULT_SITE, "/old").unwrap().unwrap();
    assert_eq!(
        old.kind(),
        RouteKind::Redirect {
            to: moved,
            status: 301
        }
    );
    assert_eq!(title(&db, moved).as_deref(), Some("M"));
    assert!(
        db.content()
            .resolve(DEFAULT_SITE, "/draft")
            .unwrap()
            .is_none()
    );
    assert!(db.content().draft(draft).unwrap().is_some());
    assert!(
        db.content()
            .resolve(DEFAULT_SITE, "/gone")
            .unwrap()
            .is_none()
    );
    assert!(db.content().get(gone).unwrap().is_none());
    assert_eq!(db.content().revisions(moved).unwrap().len(), 1);
}

#[test]
fn test_a_snapshot_keeps_the_routes_of_its_time() {
    let dir = TempDir::new("snapshot");
    let db = Database::open(&dir.0).unwrap();
    let rid = db.content().create(Entity::new("page").path("/s")).unwrap();
    let _ = db.content().publish(rid).unwrap();
    let seen = db
        .read(|r| {
            std::thread::scope(|s| {
                s.spawn(|| db.content().unpublish(rid).unwrap())
                    .join()
                    .unwrap()
            });
            Ok((
                r.content().resolve(DEFAULT_SITE, "/s")?.is_some(),
                r.content().get(rid)?.is_some(),
                r.content().draft(rid)?.is_some(),
            ))
        })
        .unwrap();
    assert_eq!(seen, (true, true, true));
    assert!(db.content().resolve(DEFAULT_SITE, "/s").unwrap().is_none());
}

fn titles(page: &nex_db::Page<nex_db::Entry>) -> Vec<String> {
    page.items()
        .iter()
        .filter_map(|e| e.field("title").and_then(Value::as_text).map(str::to_owned))
        .collect()
}

#[test]
fn test_listings_page_newest_first_and_follow_publishing() {
    let dir = TempDir::new("listings");
    let posts = {
        let db = Database::open(&dir.0).unwrap();
        let mut posts = Vec::new();
        for n in 1..=5 {
            let rid = db
                .content()
                .create(Entity::new("post").field("title", format!("p{n}")))
                .unwrap();
            let _ = db.content().publish(rid).unwrap();
            posts.push(rid);
            // Publication times one millisecond apart at least.
            std::thread::sleep(std::time::Duration::from_millis(3));
        }
        // A draft and a page of another type are not listed.
        let _ = db
            .content()
            .create(Entity::new("post").field("title", "draft"))
            .unwrap();
        let page = db
            .content()
            .create(Entity::new("page").field("title", "about"))
            .unwrap();
        let _ = db.content().publish(page).unwrap();

        let first = db
            .content()
            .list(&Listing::latest("post").limit(2))
            .unwrap();
        assert_eq!(titles(&first), ["p5", "p4"]);
        let cursor = first.next().unwrap().clone();
        // The cursor travels as text.
        let cursor = Cursor::parse(&cursor.to_string()).unwrap();
        let second = db.content().next_page(&cursor).unwrap();
        assert_eq!(titles(&second), ["p3", "p2"]);
        let third = db.content().next_page(second.next().unwrap()).unwrap();
        assert_eq!(titles(&third), ["p1"]);
        assert!(third.next().is_none());

        // Republishing an edit moves it to the front of `updated`, not of
        // `latest`.
        db.content()
            .save_draft(posts[0], Patch::new().set("title", "p1 again"))
            .unwrap();
        let _ = db.content().publish(posts[0]).unwrap();
        let updated = db
            .content()
            .list(&Listing::latest("post").updated().limit(1))
            .unwrap();
        assert_eq!(titles(&updated), ["p1 again"]);
        let latest = db
            .content()
            .list(&Listing::latest("post").limit(1))
            .unwrap();
        assert_eq!(titles(&latest), ["p5"]);
        let _ = db.content().unpublish(posts[4]).unwrap();
        posts
    };
    // Rebuilt at open.
    let db = Database::open(&dir.0).unwrap();
    let all = db.content().list(&Listing::latest("post")).unwrap();
    assert_eq!(titles(&all), ["p4", "p3", "p2", "p1 again"]);
    assert_eq!(all.items()[0].rid(), posts[3]);
    assert!(
        db.content()
            .list(&Listing::latest("post").site("other.example"))
            .unwrap()
            .items()
            .is_empty()
    );
    assert!(Cursor::parse("not a cursor").is_err());
    let _ = DEFAULT_SITE;
}
