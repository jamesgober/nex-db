//! A delete removes every revision of the entity, including ones written in
//! the same commit.

#![cfg(feature = "content")]

use std::path::PathBuf;

use nex_db::{Database, Entity, Patch};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        TempDir(std::env::temp_dir().join(format!(
            "nex-db-deletion-{name}-{}-{}",
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

/// Before 0.8 a revision written earlier in the deleting commit was not in
/// the store when the delete scanned for revisions, so it stayed for good,
/// listed, and in every backup.
#[test]
fn test_a_delete_removes_revisions_written_in_the_same_commit() {
    let t = TempDir::new("same-commit");
    let db = Database::open(&t.0).unwrap();
    // Created, published, and deleted in one commit.
    let created = db
        .commit(|tx| {
            let id = tx
                .content()
                .put(Entity::new("page").field("title", "secret").path("/a"))?;
            tx.content().delete(id)?;
            Ok(id)
        })
        .unwrap();
    // Published earlier; edited, recorded, and deleted in one commit.
    let edited = db
        .content()
        .put(Entity::new("page").field("title", "first").path("/b"))
        .unwrap();
    db.commit(|tx| {
        tx.content()
            .save_draft(edited, Patch::new().set("title", "latest, most sensitive"))?;
        let _ = tx.content().save_revision(edited, "edit")?;
        tx.content().delete(edited)
    })
    .unwrap();
    for id in [created, edited] {
        assert!(
            db.content().revisions(id).unwrap_or_default().is_empty(),
            "{id}"
        );
    }
    drop(db);
    let db = Database::open(&t.0).unwrap();
    for id in [created, edited] {
        assert!(
            db.content().revisions(id).unwrap_or_default().is_empty(),
            "{id} after reopen"
        );
    }
}
