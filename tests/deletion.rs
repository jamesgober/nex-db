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

/// Reads inside `commit` see the latest state, so two of them can straddle
/// another commit (the docs said "snapshot isolation" before 0.8).
/// `commit_serializable` is the call for a write derived from reads: the
/// straddled commit makes it run again, so it never lands on a mix.
#[test]
fn test_commit_serializable_never_lands_on_a_mix_of_two_states() {
    use std::sync::atomic::{AtomicU32, Ordering};
    let t = TempDir::new("serializable");
    let db = Database::open(&t.0).unwrap();
    let x = db.content().put(Entity::new("n").field("v", 1i64)).unwrap();
    let y = db.content().put(Entity::new("n").field("v", 1i64)).unwrap();
    let total = db.content().put(Entity::new("n").field("v", 2i64)).unwrap();
    let runs = AtomicU32::new(0);
    let value = |e: Option<nex_db::Entry>| {
        e.and_then(|e| e.field("v").and_then(|v| v.as_int()))
            .unwrap()
    };
    db.commit_serializable(|tx| {
        let first = value(tx.content().draft(x)?);
        if runs.fetch_add(1, Ordering::SeqCst) == 0 {
            // Another commit changes both between the closure's two reads.
            std::thread::scope(|s| {
                let _ = s.spawn(|| {
                    db.commit(|tx| {
                        tx.content().save_draft(x, Patch::new().set("v", 2i64))?;
                        tx.content().save_draft(y, Patch::new().set("v", 2i64))
                    })
                    .unwrap();
                });
            });
        }
        let second = value(tx.content().draft(y)?);
        tx.content()
            .save_draft(total, Patch::new().set("v", first + second))
    })
    .unwrap();
    assert!(
        runs.load(Ordering::SeqCst) >= 2,
        "the straddled attempt ran again"
    );
    let total = value(db.content().draft(total).unwrap());
    assert_eq!(total, 4, "the total matches one state, not a mix of two");
}
