//! Signed audit exports (feature `audit-export`).

#![cfg(feature = "audit-export")]

use std::path::{Path, PathBuf};

use nex_db::{AuditExport, Database, Error, SessionSpec};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        TempDir(std::env::temp_dir().join(format!(
            "nex-db-audit-export-{name}-{}-{}",
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

/// A database with a few security writes: an account, two sessions, a
/// revocation.
fn busy(dir: &Path) -> Database {
    let db = Database::open(dir).unwrap();
    let account = db.auth().sign_up("ann@example.com", PASSWORD).unwrap();
    let token = db
        .auth()
        .issue_session(account, SessionSpec::web())
        .unwrap();
    let _ = db
        .auth()
        .issue_session(account, SessionSpec::web())
        .unwrap();
    let _ = db.auth().revoke(&token).unwrap();
    db
}

#[test]
fn test_an_export_verifies_with_the_public_key_only() {
    let t = TempDir::new("verify");
    let db = busy(&t.0);
    let export = db.auth().audit_export(..).unwrap();
    let key = db.auth().audit_public_key().unwrap();
    let checked = AuditExport::from_bytes(&export.to_bytes(), &key).unwrap();
    assert_eq!(checked, export);
    let actions: Vec<&str> = checked.events().iter().map(|e| e.action()).collect();
    assert_eq!(actions[0], "account.created");
    assert!(actions.contains(&"session.issued") && actions.contains(&"session.revoked"));
    assert_eq!(checked.range(), 0..checked.chain_len());
    for (i, event) in checked.events().iter().enumerate() {
        assert_eq!(event.id(), i as u64);
        assert!(event.commit().0 > 0);
        // Ids and kinds only: never the identifier.
        assert!(!event.target().contains("ann@example.com"));
    }
    // The key is the same after a restart.
    drop(db);
    let db = Database::open(&t.0).unwrap();
    assert_eq!(db.auth().audit_public_key().unwrap(), key);
}

#[test]
fn test_a_changed_byte_or_another_key_is_refused() {
    let t = TempDir::new("tamper");
    let db = busy(&t.0);
    let bytes = db.auth().audit_export(..).unwrap().to_bytes();
    let key = db.auth().audit_public_key().unwrap();
    for at in [0, 20, bytes.len() / 2, bytes.len() - 1] {
        let mut bad = bytes.clone();
        bad[at] ^= 0x01;
        assert!(matches!(
            AuditExport::from_bytes(&bad, &key),
            Err(Error::Invalid { .. })
        ));
    }
    assert!(AuditExport::from_bytes(&bytes[..bytes.len() - 1], &key).is_err());
    let other = TempDir::new("other");
    let stranger = busy(&other.0);
    let their_key = stranger.auth().audit_public_key().unwrap();
    assert_ne!(their_key, key);
    assert!(AuditExport::from_bytes(&bytes, &their_key).is_err());
}

#[test]
fn test_consecutive_exports_join_and_ranges_clamp() {
    let t = TempDir::new("ranges");
    let db = busy(&t.0);
    let all = db.auth().audit_export(..).unwrap();
    let len = all.chain_len();
    assert!(len >= 4);
    let first = db.auth().audit_export(..2).unwrap();
    let second = db.auth().audit_export(2..).unwrap();
    assert_eq!(first.events().len(), 2);
    assert_eq!(second.events().len() as u64, len - 2);
    assert!(second.continues(&first));
    assert!(!first.continues(&second));
    let gap = db.auth().audit_export(3..).unwrap();
    assert!(!gap.continues(&first));
    // Past the end, and empty ranges.
    let past = db.auth().audit_export(len + 10..).unwrap();
    assert!(past.events().is_empty());
    assert_eq!(past.range(), len..len);
    let empty = db.auth().audit_export(1..1).unwrap();
    assert!(empty.events().is_empty());
    // More records later: the earlier export is continued by the next one.
    let account = db.auth().sign_up("bo@example.com", PASSWORD).unwrap();
    let _ = db.auth().revoke_all(account).unwrap();
    let later = db.auth().audit_export(len..).unwrap();
    assert!(!later.events().is_empty());
    assert!(later.continues(&all));
}

#[test]
fn test_a_changed_chain_file_fails_the_export() {
    let t = TempDir::new("chain");
    let db = busy(&t.0);
    drop(db);
    let chain = find(&t.0, "audit.chain").expect("the chain file");
    let mut bytes = std::fs::read(&chain).unwrap();
    let at = bytes.len() / 2;
    bytes[at] ^= 0x01;
    std::fs::write(&chain, &bytes).unwrap();
    let db = Database::open(&t.0).unwrap();
    assert!(matches!(
        db.auth().audit_export(..),
        Err(Error::Corrupt { .. })
    ));
}

fn find(dir: &Path, name: &str) -> Option<PathBuf> {
    for entry in std::fs::read_dir(dir).ok()? {
        let path = entry.ok()?.path();
        if path.file_name().is_some_and(|n| n == name) {
            return Some(path);
        }
        if path.is_dir() {
            if let Some(found) = find(&path, name) {
                return Some(found);
            }
        }
    }
    None
}
