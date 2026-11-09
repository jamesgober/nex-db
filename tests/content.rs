//! Drafts, revisions, publishing, and routes.

use std::path::PathBuf;

use nex_db::{
    Cursor, DEFAULT_SITE, Database, Entity, Error, Listing, Patch, RouteKind, Rule, Status, Type,
    Value, Visibility,
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

#[test]
fn test_translations_publish_per_locale_and_fall_back() {
    use nex_db::{Locale, SpaceSpec};
    let l = |t: &str| Locale::new(t).unwrap();
    let (en, fr, fr_ca, de) = (l("en"), l("fr"), l("fr-CA"), l("de"));
    let dir = TempDir::new("locales");
    let rid = {
        let db = Database::open(&dir.0).unwrap();
        assert_eq!(db.content().space().default_locale(), Locale::EN);
        db.content()
            .set_space(SpaceSpec::new(en).fallback(fr_ca, &[fr]).unwrap())
            .unwrap();
        let rid = db
            .content()
            .create(Entity::new("page").field("title", "Hello").path("/hello"))
            .unwrap();
        assert_eq!(db.content().draft(rid).unwrap().unwrap().locale(), en);
        let _ = db.content().publish(rid).unwrap();
        db.commit(|tx| {
            tx.content().translate(
                rid,
                fr,
                Patch::new().set("title", "Bonjour").path("/fr/bonjour"),
            )?;
            tx.content().publish_in(rid, &[fr])
        })
        .unwrap();
        // A translation cannot take a path another locale serves.
        let taken = db.commit(|tx| {
            tx.content()
                .translate(rid, de, Patch::new().path("/hello"))?;
            tx.content().publish_in(rid, &[de])
        });
        assert!(matches!(taken, Err(Error::AlreadyExists { what: "path" })));
        rid
    };
    let db = Database::open(&dir.0).unwrap();
    assert_eq!(db.content().space().default_locale(), en);
    let in_fr = db.content().get_in(rid, fr).unwrap().unwrap();
    assert_eq!(
        in_fr.field("title").and_then(Value::as_text),
        Some("Bonjour")
    );
    assert_eq!((in_fr.locale(), in_fr.fallback()), (fr, None));
    // fr-CA has nothing: its chain gives fr.
    let in_fr_ca = db.content().get_in(rid, fr_ca).unwrap().unwrap();
    assert_eq!((in_fr_ca.locale(), in_fr_ca.fallback()), (fr, Some(fr_ca)));
    // de has no chain: the entity's own locale.
    let in_de = db.content().get_in(rid, de).unwrap().unwrap();
    assert_eq!((in_de.locale(), in_de.fallback()), (en, Some(de)));
    let route = db
        .content()
        .resolve(DEFAULT_SITE, "/fr/bonjour")
        .unwrap()
        .unwrap();
    assert_eq!((route.entity(), route.locale()), (rid, fr));
    assert_eq!(
        db.content()
            .resolve(DEFAULT_SITE, "/hello")
            .unwrap()
            .unwrap()
            .locale(),
        en
    );
    assert_eq!(
        db.content()
            .revisions(rid)
            .unwrap()
            .iter()
            .map(|r| r.locale())
            .collect::<Vec<_>>(),
        [en, fr]
    );

    // Unpublishing one locale leaves the others served.
    assert!(
        db.commit(|tx| tx.content().unpublish_in(rid, &[fr]))
            .unwrap()
    );
    assert!(
        db.content()
            .resolve(DEFAULT_SITE, "/fr/bonjour")
            .unwrap()
            .is_none()
    );
    let back = db.content().get_in(rid, fr).unwrap().unwrap();
    assert_eq!(back.locale(), en);
    assert_eq!(
        db.content().draft(rid).unwrap().unwrap().status(),
        Status::Published
    );
    assert!(db.content().draft_in(rid, fr).unwrap().is_some());
    assert!(db.content().draft_in(rid, fr_ca).unwrap().is_none());
}

#[test]
fn test_types_check_kinds_unique_values_and_singletons() {
    use nex_db::{FieldType, Type};
    let dir = TempDir::new("types");
    {
        let db = Database::open(&dir.0).unwrap();
        db.content()
            .define(
                Type::new("post")
                    .field("words", FieldType::Int)
                    .field("slug", FieldType::Text)
                    .unique(),
            )
            .unwrap();
        db.content()
            .define(Type::new("settings").singleton())
            .unwrap();
        assert!(
            db.content()
                .create(Entity::new("post").field("words", "many"))
                .is_err()
        );
        let a = db
            .content()
            .create(
                Entity::new("post")
                    .field("words", 3_i64)
                    .field("slug", "hello"),
            )
            .unwrap();
        assert!(
            db.content()
                .save_draft(a, Patch::new().set("words", true))
                .is_err()
        );
        // Drafts may share a unique value; publishing may not.
        let b = db
            .content()
            .create(Entity::new("post").field("slug", "hello"))
            .unwrap();
        let _ = db.content().publish(a).unwrap();
        assert!(matches!(
            db.content().publish(b),
            Err(Error::AlreadyExists {
                what: "field value"
            })
        ));
        let _ = db.content().create(Entity::new("settings")).unwrap();
        assert!(matches!(
            db.content().create(Entity::new("settings")),
            Err(Error::AlreadyExists { what: "singleton" })
        ));
        // A type only grows.
        assert!(
            db.content()
                .define(Type::new("post").field("words", FieldType::Text))
                .is_err()
        );
        // Two published pages share a title: it cannot become unique.
        for _ in 0..2 {
            let rid = db
                .content()
                .create(Entity::new("page").field("title", "Same"))
                .unwrap();
            let _ = db.content().publish(rid).unwrap();
        }
        assert!(
            db.content()
                .define(Type::new("page").field("title", FieldType::Text).unique())
                .is_err()
        );
        // A draft edit leaves the published value taken.
        db.content()
            .save_draft(a, Patch::new().set("slug", "renamed"))
            .unwrap();
        assert!(db.content().publish(b).is_err());
        // Unpublishing frees the value.
        let _ = db.content().unpublish(a).unwrap();
        let _ = db.content().publish(b).unwrap();
        // Publishing the edit takes the new value only.
        let _ = db.content().publish(a).unwrap();
        let d = db
            .content()
            .create(Entity::new("post").field("slug", "renamed"))
            .unwrap();
        assert!(db.content().publish(d).is_err());
        db.content()
            .save_draft(a, Patch::new().set("slug", "again"))
            .unwrap();
    }
    let db = Database::open(&dir.0).unwrap();
    let post = db.content().type_named("post").unwrap();
    assert_eq!(post.fields().count(), 2);
    assert!(
        db.content()
            .create(Entity::new("post").field("words", "many"))
            .is_err()
    );
    assert!(matches!(
        db.content().create(Entity::new("settings")),
        Err(Error::AlreadyExists { what: "singleton" })
    ));
    let c = db
        .content()
        .create(Entity::new("post").field("slug", "hello"))
        .unwrap();
    assert!(db.content().publish(c).is_err());
    // After a reopen the index holds published values, not drafts: `a` is
    // published as "renamed" with a draft of "again".
    let e = db
        .content()
        .create(Entity::new("post").field("slug", "renamed"))
        .unwrap();
    assert!(db.content().publish(e).is_err());
    let f = db
        .content()
        .create(Entity::new("post").field("slug", "again"))
        .unwrap();
    let _ = db.content().publish(f).unwrap();
}

#[test]
fn test_trash_restore_and_delete() {
    let dir = TempDir::new("trash");
    let (kept, deleted) = {
        let db = Database::open(&dir.0).unwrap();
        let kept = db
            .content()
            .create(Entity::new("post").field("title", "Kept").path("/kept"))
            .unwrap();
        let _ = db.content().publish(kept).unwrap();
        db.content().trash(kept).unwrap();
        assert!(db.content().trash(kept).is_err());
        let gone = db
            .content()
            .resolve(DEFAULT_SITE, "/kept")
            .unwrap()
            .unwrap();
        assert_eq!((gone.kind(), gone.entity()), (RouteKind::Gone, kept));
        assert!(db.content().get(kept).unwrap().is_none());
        assert!(db.content().publish(kept).is_err());
        assert_eq!(
            db.content().draft(kept).unwrap().unwrap().status(),
            Status::Trashed
        );
        assert!(
            db.content()
                .list(&Listing::latest("post"))
                .unwrap()
                .items()
                .is_empty()
        );
        db.content().restore(kept).unwrap();
        assert!(
            db.content()
                .resolve(DEFAULT_SITE, "/kept")
                .unwrap()
                .is_none()
        );
        let _ = db.content().publish(kept).unwrap();
        assert_eq!(
            db.content()
                .resolve(DEFAULT_SITE, "/kept")
                .unwrap()
                .unwrap()
                .kind(),
            RouteKind::Page
        );

        let deleted = db
            .content()
            .create(Entity::new("post").field("title", "Gone").path("/gone"))
            .unwrap();
        let _ = db.content().publish(deleted).unwrap();
        db.content().delete(deleted).unwrap();
        assert!(db.content().draft(deleted).unwrap().is_none());
        assert!(db.content().revisions(deleted).unwrap().is_empty());
        assert!(db.content().delete(deleted).is_err());
        (kept, deleted)
    };
    let db = Database::open(&dir.0).unwrap();
    let gone = db
        .content()
        .resolve(DEFAULT_SITE, "/gone")
        .unwrap()
        .unwrap();
    assert_eq!((gone.kind(), gone.entity()), (RouteKind::Gone, deleted));
    assert!(db.content().draft(deleted).unwrap().is_none());
    let list = db.content().list(&Listing::latest("post")).unwrap();
    assert_eq!(list.items().len(), 1);
    assert_eq!(list.items()[0].rid(), kept);
    // Another entity may take a gone path.
    let next = db
        .content()
        .create(Entity::new("post").path("/gone"))
        .unwrap();
    let _ = db.content().publish(next).unwrap();
    assert_eq!(
        db.content()
            .resolve(DEFAULT_SITE, "/gone")
            .unwrap()
            .unwrap()
            .entity(),
        next
    );
}

#[test]
fn test_references_are_indexed_and_their_rules_apply_on_delete() {
    let dir = TempDir::new("references");
    let (author, post, gallery) = {
        let db = Database::open(&dir.0).unwrap();
        db.content()
            .define(
                Type::new("post")
                    .reference("author", Rule::Restrict)
                    .reference("hero", Rule::Detach),
            )
            .unwrap();
        db.content()
            .define(Type::new("comment").reference("on", Rule::Cascade))
            .unwrap();

        // A reference must name an entity.
        let nowhere = nex_db::Rid::from_bytes([9; 16]);
        assert!(matches!(
            db.content()
                .create(Entity::new("post").field("author", nowhere)),
            Err(Error::Invalid { .. })
        ));

        let author = db
            .content()
            .create(Entity::new("person").field("title", "Ann").path("/ann"))
            .unwrap();
        let image = db
            .content()
            .create(Entity::new("image").path("/img"))
            .unwrap();
        let post = db
            .content()
            .create(
                Entity::new("post")
                    .field("title", "Hello")
                    .field("author", author)
                    .field("hero", image)
                    .path("/hello"),
            )
            .unwrap();
        let _ = db.content().publish(post).unwrap();
        let _ = db.content().publish(image).unwrap();
        assert_eq!(db.content().referenced_by(author).unwrap(), vec![post]);
        assert_eq!(db.content().referenced_by(image).unwrap(), vec![post]);

        // Restrict: the author stays while the post names it.
        assert!(matches!(
            db.content().delete(author),
            Err(Error::Restricted { what: "entity" })
        ));
        assert!(db.content().draft(author).unwrap().is_some());

        // Detach: the image goes, and the post is published again without it.
        let before = db.content().get(post).unwrap().unwrap().revision();
        db.content().delete(image).unwrap();
        let after = db.content().get(post).unwrap().unwrap();
        assert!(after.revision() > before);
        assert!(after.field("hero").is_none());
        assert_eq!(after.field("title").and_then(Value::as_text), Some("Hello"));
        assert!(
            db.content()
                .draft(post)
                .unwrap()
                .unwrap()
                .field("hero")
                .is_none()
        );
        let route = db
            .content()
            .resolve(DEFAULT_SITE, "/hello")
            .unwrap()
            .unwrap();
        assert_eq!(route.revision(), after.revision());

        // A draft that drops the reference while the published body keeps
        // it: still a reference.
        db.content()
            .save_draft(post, Patch::new().remove("author"))
            .unwrap();
        assert_eq!(db.content().referenced_by(author).unwrap(), vec![post]);
        assert!(db.content().delete(author).is_err());

        // Cascade: deleting the post deletes its comment, by the same rules.
        let comment = db
            .content()
            .create(Entity::new("comment").field("on", post))
            .unwrap();
        let reply = db
            .content()
            .create(Entity::new("comment").field("on", comment))
            .unwrap();
        // An undeclared reference restricts.
        let gallery = db
            .content()
            .create(Entity::new("gallery").field("cover", reply))
            .unwrap();
        assert!(matches!(
            db.content().delete(post),
            Err(Error::Restricted { .. })
        ));
        assert!(db.content().draft(comment).unwrap().is_some());
        db.content()
            .save_draft(gallery, Patch::new().remove("cover"))
            .unwrap();
        assert!(db.content().referenced_by(reply).unwrap().is_empty());
        db.content().delete(post).unwrap();
        for gone in [post, comment, reply] {
            assert!(db.content().draft(gone).unwrap().is_none());
        }
        // Nothing names the author now: it can go.
        assert!(db.content().referenced_by(author).unwrap().is_empty());
        (author, post, gallery)
    };
    // The reference records survive a reopen.
    let db = Database::open(&dir.0).unwrap();
    assert!(db.content().draft(post).unwrap().is_none());
    let tag = db
        .content()
        .create(Entity::new("tag").field("by", author))
        .unwrap();
    let db_refs = db.content().referenced_by(author).unwrap();
    assert_eq!(db_refs, vec![tag]);
    assert!(db.content().delete(author).is_err());
    db.content().delete(tag).unwrap();
    db.content().delete(author).unwrap();
    assert!(db.content().draft(gallery).unwrap().is_some());
}

#[test]
fn test_a_reference_to_an_entity_deleted_concurrently_never_lands() {
    use std::{sync::Arc, thread};
    let dir = TempDir::new("references-race");
    let db = Arc::new(Database::open(&dir.0).unwrap());
    for _ in 0..20 {
        let target = db
            .content()
            .create(Entity::new("page").field("title", "T"))
            .unwrap();
        let a = {
            let db = Arc::clone(&db);
            thread::spawn(move || db.content().delete(target))
        };
        let b = {
            let db = Arc::clone(&db);
            thread::spawn(move || {
                db.content()
                    .create(Entity::new("post").field("about", target))
            })
        };
        let deleted = a.join().unwrap();
        let created = b.join().unwrap();
        // One of the two wins; never both.
        match (&deleted, &created) {
            (Ok(()), Err(Error::Invalid { .. })) => {}
            (Err(Error::Restricted { .. }), Ok(source)) => {
                assert_eq!(db.content().referenced_by(target).unwrap(), vec![*source]);
            }
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn test_page_tree_and_authors() {
    use nex_db::AccountId;
    let dir = TempDir::new("tree");
    let ann = AccountId::from_bytes([1; 16]);
    let bob = AccountId::from_bytes([2; 16]);
    let (root, docs, intro) = {
        let db = Database::open(&dir.0).unwrap();
        let root = db.content().create(Entity::new("page").path("/")).unwrap();
        let docs = db
            .content()
            .create(Entity::new("page").path("/docs").parent(root).order(2))
            .unwrap();
        let about = db
            .content()
            .create(Entity::new("page").path("/about").parent(root).order(1))
            .unwrap();
        let intro = db
            .content()
            .create(Entity::new("page").path("/docs/intro").parent(docs))
            .unwrap();
        assert_eq!(db.content().children(root), vec![about, docs]);
        assert_eq!(db.content().ancestors(intro).unwrap(), vec![docs, root]);
        assert!(db.content().ancestors(root).unwrap().is_empty());
        assert_eq!(
            db.content().draft(intro).unwrap().unwrap().parent(),
            Some(docs)
        );

        // No cycles, no parent that does not exist.
        assert!(db.content().set_parent(root, Some(intro)).is_err());
        assert!(db.content().set_parent(docs, Some(docs)).is_err());
        assert!(
            db.content()
                .set_parent(docs, Some(nex_db::Rid::from_bytes([9; 16])))
                .is_err()
        );
        // Reorder and move.
        db.commit(|tx| tx.content().set_order(docs, 0)).unwrap();
        assert_eq!(db.content().children(root), vec![docs, about]);
        db.content().set_parent(about, Some(docs)).unwrap();
        assert_eq!(db.content().children(root), vec![docs]);
        assert_eq!(db.content().children(docs), vec![intro, about]);
        db.content().set_parent(about, None).unwrap();

        // A parent stays while it has children.
        assert!(matches!(
            db.content().delete(docs),
            Err(Error::Restricted { .. })
        ));
        db.content().delete(about).unwrap();

        // Authors: listings per author, shared by every locale.
        let post = db
            .content()
            .create(Entity::new("post").author(ann).author(bob))
            .unwrap();
        let other = db
            .content()
            .create(Entity::new("post").author(bob))
            .unwrap();
        let _ = db.content().publish(post).unwrap();
        let _ = db.content().publish(other).unwrap();
        let by = |a| {
            db.content()
                .list(&Listing::latest("post").by_author(a))
                .unwrap()
                .items()
                .iter()
                .map(|e| e.rid())
                .collect::<Vec<_>>()
        };
        assert_eq!(by(ann), vec![post]);
        assert_eq!(by(bob), vec![other, post]);
        assert_eq!(
            db.content().get(post).unwrap().unwrap().authors(),
            &[ann, bob]
        );
        db.content().set_authors(post, &[bob]).unwrap();
        assert!(by(ann).is_empty());
        // The author filter travels in the cursor.
        let first = db
            .content()
            .list(&Listing::latest("post").by_author(bob).limit(1))
            .unwrap();
        let cursor = Cursor::parse(&first.next().unwrap().to_string()).unwrap();
        let second = db.content().next_page(&cursor).unwrap();
        assert_eq!(second.items()[0].rid(), post);
        (root, docs, intro)
    };
    // Rebuilt at open.
    let db = Database::open(&dir.0).unwrap();
    assert_eq!(db.content().children(root), vec![docs]);
    assert_eq!(db.content().ancestors(intro).unwrap(), vec![docs, root]);
    assert_eq!(
        db.content()
            .list(&Listing::latest("post").by_author(bob))
            .unwrap()
            .items()
            .len(),
        2
    );
}

#[test]
fn test_terms_tag_entities_and_list_them() {
    let dir = TempDir::new("terms");
    let (rust, post, old) = {
        let db = Database::open(&dir.0).unwrap();
        db.content()
            .define(Type::new("post").terms("tags", "tag"))
            .unwrap();
        let tag = |name: &str| {
            let rid = db
                .content()
                .create(
                    Entity::new("tag")
                        .field("name", name)
                        .path(format!("/tags/{name}")),
                )
                .unwrap();
            let _ = db.content().publish(rid).unwrap();
            rid
        };
        let rust = tag("rust");
        let db_tag = tag("databases");
        let page = db.content().create(Entity::new("page")).unwrap();

        // Only terms of the field's taxonomy.
        assert!(matches!(
            db.content()
                .create(Entity::new("post").field("tags", [rust, page])),
            Err(Error::Invalid { .. })
        ));
        assert!(
            db.content()
                .create(Entity::new("post").field("tags", "rust"))
                .is_err()
        );

        let old = db
            .content()
            .create(Entity::new("post").field("tags", [rust]))
            .unwrap();
        let post = db
            .content()
            .create(Entity::new("post").field("tags", [rust, db_tag]))
            .unwrap();
        let _ = db.content().publish(old).unwrap();
        let _ = db.content().publish(post).unwrap();
        let tagged = |t| {
            db.content()
                .list(&Listing::latest("post").term(t))
                .unwrap()
                .items()
                .iter()
                .map(|e| e.rid())
                .collect::<Vec<_>>()
        };
        assert_eq!(tagged(rust), vec![post, old]);
        assert_eq!(tagged(db_tag), vec![post]);
        assert_eq!(
            db.content()
                .get(post)
                .unwrap()
                .unwrap()
                .field("tags")
                .and_then(Value::as_list)
                .map(<[Value]>::len),
            Some(2)
        );

        // Only published bodies count: a draft change waits for publishing.
        db.content()
            .save_draft(old, Patch::new().set("tags", Value::List(Vec::new())))
            .unwrap();
        assert_eq!(tagged(rust), vec![post, old]);
        let _ = db.content().publish(old).unwrap();
        assert_eq!(tagged(rust), vec![post]);

        // Deleting a term takes it out of every list.
        db.content().delete(db_tag).unwrap();
        let tags = db.content().get(post).unwrap().unwrap();
        assert_eq!(
            tags.field("tags").and_then(Value::as_list),
            Some(&[Value::Entity(rust)][..])
        );
        assert!(tagged(db_tag).is_empty());
        (rust, post, old)
    };
    // Rebuilt at open.
    let db = Database::open(&dir.0).unwrap();
    let page = db
        .content()
        .list(&Listing::latest("post").term(rust))
        .unwrap();
    assert_eq!(page.items().len(), 1);
    assert_eq!(page.items()[0].rid(), post);
    assert!(db.content().get(old).unwrap().is_some());
    assert_eq!(
        db.content().type_named("post").unwrap().taxonomy("tags"),
        Some("tag")
    );
}

#[test]
fn test_scheduled_publishing_fires_on_time() {
    use nex_db::Action;
    use std::time::{Duration, SystemTime};
    let dir = TempDir::new("schedule");
    let wait_for = |db: &Database, rid, published: bool| {
        for _ in 0..100 {
            if db.content().get(rid).unwrap().is_some() == published {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    };
    let (later, gone) = {
        let db = Database::open(&dir.0).unwrap();
        let soon = db
            .content()
            .create(Entity::new("post").field("title", "Soon").path("/soon"))
            .unwrap();
        db.content()
            .schedule(
                soon,
                Action::Publish,
                SystemTime::now() + Duration::from_millis(300),
            )
            .unwrap();
        let draft = db.content().draft(soon).unwrap().unwrap();
        assert_eq!(draft.scheduled().map(|s| s.0), Some(Action::Publish));
        assert!(db.content().get(soon).unwrap().is_none());
        assert!(wait_for(&db, soon, true), "never published");
        assert!(
            db.content()
                .draft(soon)
                .unwrap()
                .unwrap()
                .scheduled()
                .is_none()
        );
        assert!(
            db.content()
                .resolve(DEFAULT_SITE, "/soon")
                .unwrap()
                .is_some()
        );

        // Unpublish in the past: at once.
        db.content()
            .schedule(
                soon,
                Action::Unpublish,
                SystemTime::now() - Duration::from_secs(5),
            )
            .unwrap();
        assert!(wait_for(&db, soon, false), "never unpublished");

        // Cancelled schedules do nothing; trash drops them.
        let cancelled = db.content().create(Entity::new("post")).unwrap();
        let at = SystemTime::now() + Duration::from_millis(200);
        db.commit(|tx| {
            tx.content().schedule(cancelled, Action::Publish, at)?;
            tx.content().cancel_schedule(cancelled).map(|_| ())
        })
        .unwrap();
        // A schedule that cannot run is dropped: its path is taken.
        let blocked = db
            .content()
            .create(Entity::new("post").path("/taken"))
            .unwrap();
        let taker = db
            .content()
            .create(Entity::new("post").path("/taken-later"))
            .unwrap();
        let _ = db.content().publish(taker).unwrap();
        db.content().set_path(taker, "/taken").unwrap();
        db.content().schedule(blocked, Action::Publish, at).unwrap();
        // Wait for the blocked schedule to be dropped (a loaded machine's
        // clock can step, so allow a few seconds).
        for _ in 0..100 {
            if db
                .content()
                .draft(blocked)
                .unwrap()
                .unwrap()
                .scheduled()
                .is_none()
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(db.content().get(cancelled).unwrap().is_none());
        assert!(db.content().get(blocked).unwrap().is_none());
        assert!(
            db.content()
                .draft(blocked)
                .unwrap()
                .unwrap()
                .scheduled()
                .is_none()
        );

        // Schedules survive a reopen.
        let later = db.content().create(Entity::new("post")).unwrap();
        db.content()
            .schedule(
                later,
                Action::Publish,
                SystemTime::now() + Duration::from_millis(800),
            )
            .unwrap();
        (later, soon)
    };
    let db = Database::open(&dir.0).unwrap();
    assert!(db.content().get(later).unwrap().is_none());
    assert!(wait_for(&db, later, true), "never published after reopen");
    assert!(db.content().get(gone).unwrap().is_none());
}

/// Two doctors on call; each goes off call only if the other is still on.
/// Both read before either commits.
fn go_off_call(serializable: bool) -> (bool, bool) {
    use std::sync::{Arc, Barrier};
    let dir = TempDir::new(if serializable {
        "skew-serial"
    } else {
        "skew-si"
    });
    let db = Arc::new(Database::open(&dir.0).unwrap());
    let doctor = || {
        db.content()
            .create(Entity::new("doctor").field("on_call", true))
            .unwrap()
    };
    let (a, b) = (doctor(), doctor());
    let barrier = Arc::new(Barrier::new(2));
    let run = |me: nex_db::Rid, other: nex_db::Rid| {
        let db = Arc::clone(&db);
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            let mut first = true;
            let body = |tx: &mut nex_db::Transaction<'_>| {
                let on = |e: Option<nex_db::Entry>| {
                    e.and_then(|e| e.field("on_call").and_then(Value::as_bool))
                        .unwrap_or(false)
                };
                let both = on(tx.content().draft(me)?) && on(tx.content().draft(other)?);
                if std::mem::take(&mut first) {
                    barrier.wait();
                }
                if both {
                    tx.content()
                        .save_draft(me, Patch::new().set("on_call", false))?;
                }
                Ok(())
            };
            if serializable {
                db.commit_serializable(body)
            } else {
                db.commit(body)
            }
        })
    };
    let (ta, tb) = (run(a, b), run(b, a));
    ta.join().unwrap().unwrap();
    tb.join().unwrap().unwrap();
    let on = |rid| {
        db.content()
            .draft(rid)
            .unwrap()
            .unwrap()
            .field("on_call")
            .and_then(Value::as_bool)
            .unwrap()
    };
    (on(a), on(b))
}

#[test]
fn test_commit_serializable_refuses_write_skew() {
    // Snapshot isolation lets both go: nobody is left on call.
    assert_eq!(go_off_call(false), (false, false));
    // Serializable: the second runs again, sees the first gone, and stays.
    let (a, b) = go_off_call(true);
    assert!(a != b, "exactly one stays on call: {a} {b}");
}

#[test]
fn test_reads_never_see_a_head_before_its_revision() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let dir = TempDir::new("read-race");
    let db = Arc::new(Database::open(&dir.0).unwrap());
    let rid = db
        .content()
        .create(Entity::new("post").field("n", 0_i64).path("/p"))
        .unwrap();
    let _ = db.content().publish(rid).unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let started = Arc::new(std::sync::Barrier::new(2));
    let reader = {
        let (db, done, started) = (Arc::clone(&db), Arc::clone(&done), Arc::clone(&started));
        std::thread::spawn(move || {
            started.wait();
            let mut reads = 0u64;
            loop {
                // Every read finds the entity; never an error.
                let entry = db.content().get(rid).unwrap().unwrap();
                assert!(entry.field("n").is_some());
                reads += 1;
                if done.load(Ordering::Acquire) {
                    return reads;
                }
            }
        })
    };
    started.wait();
    for n in 1..200_i64 {
        db.commit(|tx| {
            tx.content().save_draft(rid, Patch::new().set("n", n))?;
            tx.content().publish(rid).map(|_| ())
        })
        .unwrap();
    }
    done.store(true, Ordering::Release);
    assert!(reader.join().unwrap() > 0);
}

#[test]
fn test_sticky_entities_lead_sticky_first_listings_across_pages() {
    let dir = TempDir::new("sticky");
    let db = Database::open(&dir.0).unwrap();
    let mut rids = Vec::new();
    for i in 0..5 {
        let mut entity = Entity::new("post").field("title", format!("p{i}"));
        if i == 1 {
            entity = entity.sticky();
        }
        let rid = db.content().create(entity).unwrap();
        let _ = db.content().publish(rid).unwrap();
        rids.push(rid);
    }
    db.content().set_sticky(rids[3], true).unwrap();
    assert!(db.content().get(rids[3]).unwrap().unwrap().sticky());
    let ids = |listing: Listing| -> Vec<nex_db::Rid> {
        db.content()
            .stream(listing)
            .map(|e| e.unwrap().rid())
            .collect()
    };
    // Newest first; sticky ones first only when asked, and once each.
    let plain = ids(Listing::latest("post").limit(2));
    assert_eq!(plain, [rids[4], rids[3], rids[2], rids[1], rids[0]]);
    let sticky = ids(Listing::latest("post").sticky_first().limit(2));
    assert_eq!(sticky, [rids[3], rids[1], rids[4], rids[2], rids[0]]);
    // The cursor keeps the sticky order through its text form.
    let first = db
        .content()
        .list(&Listing::latest("post").sticky_first().limit(1))
        .unwrap();
    let cursor = Cursor::parse(&first.next().unwrap().to_string()).unwrap();
    let second = db.content().next_page(&cursor).unwrap();
    assert_eq!(second.items()[0].rid(), rids[1]);
    db.content().set_sticky(rids[3], false).unwrap();
    let sticky = ids(Listing::latest("post").sticky_first());
    assert_eq!(sticky, [rids[1], rids[4], rids[3], rids[2], rids[0]]);
    // The flag survives a reopen.
    drop(db);
    let db = Database::open(&dir.0).unwrap();
    assert!(db.content().get(rids[1]).unwrap().unwrap().sticky());
    assert!(!db.content().get(rids[3]).unwrap().unwrap().sticky());
}

#[test]
fn test_outdated_lists_translations_older_than_their_source() {
    use nex_db::Locale;
    let fr = Locale::new("fr").unwrap();
    let dir = TempDir::new("outdated");
    let db = Database::open(&dir.0).unwrap();
    let rid = db
        .content()
        .create(Entity::new("page").field("title", "Hello"))
        .unwrap();
    let _ = db.content().publish(rid).unwrap();
    db.commit(|tx| {
        tx.content()
            .translate(rid, fr, Patch::new().set("title", "Bonjour"))
    })
    .unwrap();
    let outdated = |db: &Database| -> Vec<(nex_db::Rid, Locale)> {
        db.content()
            .list(&Listing::outdated(fr))
            .unwrap()
            .items()
            .iter()
            .map(|e| (e.rid(), e.locale()))
            .collect()
    };
    assert!(outdated(&db).is_empty());
    db.content()
        .save_draft(rid, Patch::new().set("title", "Hello again"))
        .unwrap();
    let _ = db.content().publish(rid).unwrap();
    assert_eq!(outdated(&db), [(rid, fr)]);
    // Updating the translation brings it up to date.
    db.commit(|tx| {
        tx.content()
            .translate(rid, fr, Patch::new().set("title", "Rebonjour"))
    })
    .unwrap();
    assert!(outdated(&db).is_empty());
}

#[test]
fn test_get_many_reads_in_order_with_gaps() {
    use nex_db::Locale;
    let dir = TempDir::new("many");
    let db = Database::open(&dir.0).unwrap();
    let a = db
        .content()
        .create(Entity::new("post").field("title", "a"))
        .unwrap();
    let b = db
        .content()
        .create(Entity::new("post").field("title", "b"))
        .unwrap();
    let _ = db.content().publish(a).unwrap();
    let got = db.content().get_many(&[b, a, b], Locale::EN).unwrap();
    assert!(got[0].is_none() && got[2].is_none());
    assert_eq!(got[1].as_ref().map(nex_db::Entry::rid), Some(a));
    let many = vec![a; 1001];
    assert!(matches!(
        db.content().get_many(&many, Locale::EN),
        Err(Error::Invalid { .. })
    ));
}

#[test]
fn test_manual_redirects_resolve_and_can_be_removed() {
    let dir = TempDir::new("redirects");
    let db = Database::open(&dir.0).unwrap();
    let rid = db
        .content()
        .create(Entity::new("page").field("title", "Home").path("/home"))
        .unwrap();
    let _ = db.content().publish(rid).unwrap();
    db.content()
        .add_redirect(DEFAULT_SITE, "/old-home", rid, 308)
        .unwrap();
    let route = db
        .content()
        .resolve(DEFAULT_SITE, "/old-home")
        .unwrap()
        .unwrap();
    assert_eq!(
        route.kind(),
        RouteKind::Redirect {
            to: rid,
            status: 308
        }
    );
    // Not over a page, not with another status, not to nothing.
    assert!(matches!(
        db.content().add_redirect(DEFAULT_SITE, "/home", rid, 301),
        Err(Error::AlreadyExists { what: "path" })
    ));
    assert!(
        db.content()
            .add_redirect(DEFAULT_SITE, "/x", rid, 200)
            .is_err()
    );
    assert!(
        db.content()
            .add_redirect(DEFAULT_SITE, "/x", nex_db::Rid::from_bytes([9; 16]), 301)
            .is_err()
    );
    assert!(db.content().remove_route(DEFAULT_SITE, "/home").is_err());
    assert!(
        db.content()
            .remove_route(DEFAULT_SITE, "/old-home")
            .unwrap()
    );
    assert!(
        !db.content()
            .remove_route(DEFAULT_SITE, "/old-home")
            .unwrap()
    );
    assert!(
        db.content()
            .resolve(DEFAULT_SITE, "/old-home")
            .unwrap()
            .is_none()
    );
    // A redirect survives a reopen.
    db.content()
        .add_redirect(DEFAULT_SITE, "/start", rid, 302)
        .unwrap();
    drop(db);
    let db = Database::open(&dir.0).unwrap();
    assert_eq!(
        db.content()
            .resolve(DEFAULT_SITE, "/start")
            .unwrap()
            .unwrap()
            .kind(),
        RouteKind::Redirect {
            to: rid,
            status: 302
        }
    );
}

#[test]
fn test_search_ranks_published_bodies_per_locale() {
    use nex_db::{FieldType, Locale, Search};
    let fr = Locale::new("fr").unwrap();
    let dir = TempDir::new("search");
    let post = Type::new("post")
        .field("title", FieldType::Text)
        .searchable(3)
        .field("body", FieldType::Text)
        .searchable(1);
    let found = |db: &Database, locale: Locale, query: Search| -> Vec<nex_db::Rid> {
        db.content()
            .search(locale, &query)
            .unwrap()
            .items()
            .iter()
            .map(nex_db::Hit::rid)
            .collect()
    };
    let (a, b, c) = {
        let db = Database::open(&dir.0).unwrap();
        db.content().define(post.clone()).unwrap();
        let make = |kind: &str, title: &str, body: &str| {
            let rid = db
                .content()
                .create(Entity::new(kind).field("title", title).field("body", body))
                .unwrap();
            let _ = db.content().publish(rid).unwrap();
            rid
        };
        let a = make("post", "Running a database", "Notes on running things.");
        let b = make(
            "post",
            "Garden notes",
            "The database runs in the garden shed.",
        );
        let c = make("post", "Cooking", "Nothing about runs here, or databases.");
        // An undeclared type is not indexed; neither is a draft.
        let _ = make("page", "Running database page", "running database");
        let _ = db
            .content()
            .create(Entity::new("post").field("title", "Running database draft"))
            .unwrap();
        // Every word must match; word forms match; the title weighs more, and
        // of two bodies the shorter (c) ranks higher.
        assert_eq!(
            found(&db, Locale::EN, Search::new("RUNS databases")),
            [a, c, b]
        );
        assert_eq!(found(&db, Locale::EN, Search::new("garden database")), [b]);
        assert!(found(&db, Locale::EN, Search::new("garden zebra")).is_empty());
        // Stopwords alone match nothing.
        assert!(found(&db, Locale::EN, Search::new("the of")).is_empty());
        let page = db
            .content()
            .search(Locale::EN, &Search::new("database").limit(1).offset(1))
            .unwrap();
        assert_eq!((page.total(), page.items().len()), (3, 1));
        assert_eq!(page.items()[0].rid(), c);
        assert!(found(&db, Locale::EN, Search::new("database").kind("page")).is_empty());
        // A translation is searched in its own locale, without stemming.
        db.commit(|tx| {
            tx.content()
                .translate(c, fr, Patch::new().set("title", "Cuisine du jardin"))?;
            tx.content().publish_in(c, &[fr])
        })
        .unwrap();
        assert_eq!(found(&db, fr, Search::new("JARDIN")), [c]);
        assert!(found(&db, fr, Search::new("jardins")).is_empty());
        // Unpublishing takes it out.
        let _ = db.content().unpublish(a).unwrap();
        assert_eq!(found(&db, Locale::EN, Search::new("running")), [c, b]);
        (a, b, c)
    };
    // Rebuilt at open; a new weight indexes again.
    let db = Database::open(&dir.0).unwrap();
    assert_eq!(found(&db, Locale::EN, Search::new("database")), [c, b]);
    assert_eq!(found(&db, fr, Search::new("cuisine")), [c]);
    let _ = db.content().publish(a).unwrap();
    db.content()
        .define(
            Type::new("post")
                .field("title", FieldType::Text)
                .searchable(1)
                .field("body", FieldType::Text)
                .searchable(10),
        )
        .unwrap();
    assert_eq!(found(&db, Locale::EN, Search::new("notes")), [a, b]);
    // Only text fields are searchable.
    assert!(
        db.content()
            .define(Type::new("count").field("n", FieldType::Int).searchable(2))
            .is_err()
    );
    assert!(
        db.content()
            .search(Locale::EN, &Search::new("x ".repeat(600)))
            .is_err()
    );
}
