//! Erasing an account: its records go and its data key is destroyed.

use std::path::PathBuf;

use nex_db::{ApiKeyCheck, Database, PasswordCheck, RevokeReason, SessionSpec, SignIn, Validation};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        TempDir(std::env::temp_dir().join(format!(
            "nex-db-erasure-{name}-{}-{}",
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

fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.file_name().is_some_and(|n| n == "LOCK") {
            continue;
        }
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&path, &to.join(entry.file_name()));
        } else {
            let _ = std::fs::copy(&path, to.join(entry.file_name())).unwrap();
        }
    }
}

#[test]
fn test_an_erased_account_is_gone_everywhere_and_stays_gone() {
    let dir = TempDir::new("erase");
    let copy = TempDir::new("erase-copy");
    let (ann, bob, key, code) = {
        let db = Database::open(&dir.0).unwrap();
        let auth = db.auth();
        let hash = auth.hash_password(PASSWORD).unwrap();
        let ann = auth.create_account("ann@example.com", &hash).unwrap();
        let bob = auth.create_account("bob@example.com", &hash).unwrap();
        auth.add_identifier(ann, "ann").unwrap();
        let SignIn::Success { token, .. } = auth
            .sign_in("ann@example.com", PASSWORD, SessionSpec::web())
            .unwrap()
        else {
            panic!("ann signs in");
        };
        let codes = auth.new_recovery_codes(ann).unwrap();
        let code = codes.codes().next().unwrap().to_owned();
        let key = auth.create_api_key(ann, &["read"], None).unwrap();

        auth.erase_account(ann).unwrap();
        assert_eq!(
            auth.validate(&token).unwrap(),
            Validation::Revoked {
                reason: RevokeReason::Erased
            }
        );
        assert!(auth.account(ann).unwrap().is_none());
        assert_eq!(
            auth.verify_password("ann@example.com", PASSWORD).unwrap(),
            PasswordCheck::Failed
        );
        assert_eq!(
            auth.verify_password("ann", PASSWORD).unwrap(),
            PasswordCheck::Failed
        );
        assert!(!matches!(
            auth.validate_api_key(key.as_str()).unwrap(),
            ApiKeyCheck::Valid { .. }
        ));
        assert!(!auth.use_recovery_code(ann, &code).unwrap_or(false));
        assert!(auth.erase_account(ann).is_err());
        // Others are untouched, and the identifiers are free again.
        assert!(matches!(
            auth.verify_password("bob@example.com", PASSWORD).unwrap(),
            PasswordCheck::Verified(a) if a == bob
        ));
        let again = auth.create_account("ann@example.com", &hash).unwrap();
        assert_ne!(again, ann);
        (ann, bob, key.as_str().to_owned(), code)
    };
    copy_dir(&dir.0, &copy.0);
    // A reopen replays the log without the destroyed key; a copy of the
    // files brings nothing back.
    for path in [&dir.0, &copy.0] {
        let db = Database::open(path).unwrap();
        let auth = db.auth();
        assert!(auth.account(ann).unwrap().is_none());
        assert!(auth.account(bob).unwrap().is_some());
        assert!(!matches!(
            auth.validate_api_key(&key).unwrap(),
            ApiKeyCheck::Valid { .. }
        ));
        assert!(!auth.use_recovery_code(ann, &code).unwrap_or(false));
        assert!(matches!(
            auth.sign_in("bob@example.com", PASSWORD, SessionSpec::web())
                .unwrap(),
            SignIn::Success { .. }
        ));
        // The new account under ann's address signs in with its own key.
        assert!(matches!(
            auth.verify_password("ann@example.com", PASSWORD).unwrap(),
            PasswordCheck::Verified(a) if a != ann
        ));
    }
}
