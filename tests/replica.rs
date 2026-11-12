//! Read replicas: a database restored from a backup of a primary, following
//! the primary's commits through shipments.

#![cfg(all(feature = "auth", feature = "content"))]

use std::path::PathBuf;

use nex_db::{
    Database, Entity, Error, Patch, Position, Replica, RestorePoint, RevokeReason, SessionSpec,
    SignIn, Validation,
};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        TempDir(std::env::temp_dir().join(format!(
            "nex-db-replica-{name}-{}-{}",
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

/// Ship everything the replica lacks, in as many shipments as it takes.
fn follow(primary: &Database, replica: &Replica) {
    loop {
        let mut shipment = Vec::new();
        let shipped = primary.ship(replica.position(), &mut shipment).unwrap();
        let at = replica.receive(&mut shipment.as_slice()).unwrap();
        assert_eq!(at, shipped);
        if at == primary.position() {
            return;
        }
    }
}

fn open_pair(t: &TempDir) -> (Database, Replica) {
    let primary = Database::open(t.at("primary")).unwrap();
    let _ = primary
        .auth()
        .sign_up("seed@example.com", PASSWORD)
        .unwrap();
    let _ = primary.backup(t.at("backup")).unwrap();
    let _ = nex_db::restore(t.at("backup"), t.at("replica"), RestorePoint::Latest).unwrap();
    let replica = nex_db::open_replica(t.at("replica")).unwrap();
    (primary, replica)
}

#[test]
fn test_a_replica_follows_commits_and_serves_reads() {
    let t = TempDir::new("follow");
    let (primary, replica) = open_pair(&t);
    assert_eq!(replica.position(), primary.position());

    let account = primary.auth().sign_up("ann@example.com", PASSWORD).unwrap();
    let SignIn::Success { token, .. } = primary
        .auth()
        .sign_in("ann@example.com", PASSWORD, SessionSpec::web())
        .unwrap()
    else {
        panic!("sign-in failed");
    };
    let page = primary
        .content()
        .put(Entity::new("page").field("title", "Hello").path("/hello"))
        .unwrap();
    // Not shipped yet.
    assert!(replica.content().get(page).unwrap().is_none());
    assert!(matches!(
        replica.auth().validate(&token).unwrap(),
        Validation::Unknown
    ));

    follow(&primary, &replica);
    assert_eq!(replica.position(), primary.position());
    let entry = replica.content().get(page).unwrap().expect("shipped");
    assert_eq!(
        entry.field("title").and_then(|v| v.as_text()),
        Some("Hello")
    );
    assert!(
        replica
            .content()
            .resolve(nex_db::DEFAULT_SITE, "/hello")
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        replica.auth().validate(&token).unwrap(),
        Validation::Valid(s) if s.account() == account
    ));

    // A revocation reaches the replica with the next shipment.
    let _ = primary.auth().revoke(&token).unwrap();
    follow(&primary, &replica);
    assert!(matches!(
        replica.auth().validate(&token).unwrap(),
        Validation::Revoked {
            reason: RevokeReason::Revoked
        }
    ));

    // An empty shipment changes nothing.
    let mut shipment = Vec::new();
    assert_eq!(
        primary.ship(replica.position(), &mut shipment).unwrap(),
        primary.position()
    );
    assert_eq!(
        replica.receive(&mut shipment.as_slice()).unwrap(),
        primary.position()
    );
}

#[test]
fn test_a_replica_refuses_writes() {
    let t = TempDir::new("writes");
    let (_primary, replica) = open_pair(&t);
    assert!(matches!(
        replica.content().put(Entity::new("page").path("/x")),
        Err(Error::ReadOnlyReplica)
    ));
    assert!(matches!(
        replica.auth().sign_up("bo@example.com", PASSWORD),
        Err(Error::ReadOnlyReplica)
    ));
    assert_eq!(Error::ReadOnlyReplica.code(), "NEX-1013");
}

#[test]
fn test_a_changed_frame_is_refused_and_a_good_shipment_still_applies() {
    let t = TempDir::new("tamper");
    let (primary, replica) = open_pair(&t);
    let page = primary
        .content()
        .put(Entity::new("page").field("title", "Hello").path("/hello"))
        .unwrap();
    let mut shipment = Vec::new();
    let _ = primary.ship(replica.position(), &mut shipment).unwrap();
    let before = replica.position();
    // Every byte after the preamble is sealed: flip one in each place.
    for at in [30, shipment.len() / 2, shipment.len() - 1] {
        let mut bad = shipment.clone();
        bad[at] ^= 0x01;
        assert!(replica.receive(&mut bad.as_slice()).is_err(), "byte {at}");
        assert_eq!(replica.position(), before);
    }
    // Frames from another shipment of the same commits do not splice in.
    let mut other = Vec::new();
    let _ = primary.ship(before, &mut other).unwrap();
    let mut spliced = shipment[..26].to_vec();
    spliced.extend_from_slice(&other[26..]);
    assert!(replica.receive(&mut spliced.as_slice()).is_err());
    assert_eq!(replica.position(), before);

    assert_eq!(
        replica.receive(&mut shipment.as_slice()).unwrap(),
        primary.position()
    );
    assert!(replica.content().get(page).unwrap().is_some());
}

#[test]
fn test_a_shipment_cut_short_commits_what_arrived_whole() {
    let t = TempDir::new("cut");
    let (primary, replica) = open_pair(&t);
    let pages: Vec<_> = (0..5)
        .map(|i| {
            primary
                .content()
                .put(Entity::new("page").path(format!("/p{i}")))
                .unwrap()
        })
        .collect();
    let mut shipment = Vec::new();
    let _ = primary.ship(replica.position(), &mut shipment).unwrap();
    let cut = &shipment[..shipment.len() * 2 / 3];
    let at = replica.receive(&mut &cut[..]).unwrap();
    assert!(at > Position::from_u64(0) && at < primary.position());
    // Whatever was committed is whole, and the rest follows.
    follow(&primary, &replica);
    for page in pages {
        assert!(replica.content().get(page).unwrap().is_some());
    }
}

#[test]
fn test_a_shipment_from_another_database_or_position_is_refused() {
    let t = TempDir::new("other");
    let (primary, replica) = open_pair(&t);
    let _ = primary
        .content()
        .put(Entity::new("page").path("/a"))
        .unwrap();

    // Another database, under another key.
    let stranger = Database::open(t.at("stranger")).unwrap();
    let _ = stranger
        .content()
        .put(Entity::new("page").path("/b"))
        .unwrap();
    let mut shipment = Vec::new();
    let _ = stranger.ship(replica.position(), &mut shipment);
    if !shipment.is_empty() {
        assert!(matches!(
            replica.receive(&mut shipment.as_slice()),
            Err(Error::Invalid { .. })
        ));
    }

    // The primary's commits, but from another position.
    follow(&primary, &replica);
    let _ = primary
        .content()
        .put(Entity::new("page").path("/c"))
        .unwrap();
    let mut early = Vec::new();
    let _ = primary
        .ship(Position::from_u64(replica.position().get() - 1), &mut early)
        .unwrap();
    assert!(matches!(
        replica.receive(&mut early.as_slice()),
        Err(Error::Invalid { .. })
    ));
    follow(&primary, &replica);
    assert_eq!(replica.position(), primary.position());
}

#[test]
fn test_a_replica_restarts_and_is_promoted() {
    let t = TempDir::new("restart");
    let (primary, replica) = open_pair(&t);
    let a = primary
        .content()
        .put(Entity::new("page").path("/a"))
        .unwrap();
    follow(&primary, &replica);
    drop(replica);
    let b = primary
        .content()
        .put(Entity::new("page").path("/b"))
        .unwrap();
    let replica = nex_db::open_replica(t.at("replica")).unwrap();
    follow(&primary, &replica);
    assert!(replica.content().get(a).unwrap().is_some());
    assert!(replica.content().get(b).unwrap().is_some());

    // Promotion: the replica's directory opens as a database that writes.
    let at = replica.position();
    drop(replica);
    let promoted = Database::open(t.at("replica")).unwrap();
    assert_eq!(promoted.position(), at);
    let c = promoted
        .content()
        .put(Entity::new("page").path("/c"))
        .unwrap();
    assert!(promoted.content().get(c).unwrap().is_some());
}

#[test]
fn test_a_replica_behind_a_checkpoint_is_told_to_reseed() {
    let t = TempDir::new("behind");
    let primary = Database::builder(t.at("primary"))
        .checkpoint_every(64 * 1024)
        .open()
        .unwrap();
    let _ = primary
        .auth()
        .sign_up("seed@example.com", PASSWORD)
        .unwrap();
    let _ = primary.backup(t.at("backup")).unwrap();
    let _ = nex_db::restore(t.at("backup"), t.at("replica"), RestorePoint::Latest).unwrap();
    let replica = nex_db::open_replica(t.at("replica")).unwrap();
    let body = "x".repeat(4096);
    for i in 0..200 {
        let _ = primary
            .content()
            .put(
                Entity::new("page")
                    .field("body", body.as_str())
                    .path(format!("/p{i}")),
            )
            .unwrap();
    }
    let mut shipment = Vec::new();
    assert!(matches!(
        primary.ship(replica.position(), &mut shipment),
        Err(Error::ReplicaBehind { .. })
    ));
}

/// A small deterministic generator, so a failure repeats.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Two machines, simulated: the primary commits a random mix while the
/// replica receives shipments, some cut short, some received twice, and
/// restarts now and then. At every checked position the replica answers
/// every read exactly as the primary did at that position.
#[test]
fn test_simulated_follower_matches_the_primary_at_every_checked_position() {
    let t = TempDir::new("simulation");
    let (primary, mut replica) = open_pair(&t);
    let mut rng = Rng(std::env::var("NEX_REPLICA_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x5EED));
    let rounds: usize = std::env::var("NEX_REPLICA_ROUNDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    let mut pages: Vec<(nex_db::EntityId, String)> = Vec::new();
    let mut tokens: Vec<nex_db::Token> = Vec::new();
    let account = primary.auth().sign_up("sim@example.com", PASSWORD).unwrap();
    let mut checked = 0;
    for round in 0..rounds {
        match rng.below(10) {
            0..=3 => {
                let path = format!("/p{round}");
                let id = primary
                    .content()
                    .put(Entity::new("page").field("n", round as i64).path(&path))
                    .unwrap();
                pages.push((id, path));
            }
            4 if !pages.is_empty() => {
                let (id, _) = pages[rng.below(pages.len() as u64) as usize].clone();
                primary
                    .content()
                    .save_draft(id, Patch::new().set("n", -(round as i64)))
                    .unwrap();
                let _ = primary.content().publish(id).unwrap();
            }
            5 if !pages.is_empty() => {
                let (id, _) = pages[rng.below(pages.len() as u64) as usize].clone();
                let _ = primary.content().unpublish(id).unwrap();
            }
            6 => tokens.push(
                primary
                    .auth()
                    .issue_session(account, SessionSpec::web())
                    .unwrap(),
            ),
            7 if !tokens.is_empty() => {
                let token = &tokens[rng.below(tokens.len() as u64) as usize];
                let _ = primary.auth().revoke(token).unwrap();
            }
            _ => {}
        }
        // Ship now and then, in any of several ways.
        if rng.below(3) == 0 {
            let mut shipment = Vec::new();
            let _ = primary.ship(replica.position(), &mut shipment).unwrap();
            match rng.below(4) {
                0 => {
                    let cut = rng.below(shipment.len() as u64) as usize;
                    let _ = replica.receive(&mut &shipment[..cut]);
                }
                1 => {
                    let _ = replica.receive(&mut shipment.as_slice()).unwrap();
                    // The same shipment again: now from another position,
                    // unless it was empty.
                    let _ = replica.receive(&mut shipment.as_slice());
                }
                _ => {
                    let _ = replica.receive(&mut shipment.as_slice()).unwrap();
                }
            }
        }
        if rng.below(40) == 0 {
            drop(replica);
            replica = nex_db::open_replica(t.at("replica")).unwrap();
        }
        // Check: bring the replica level and compare every read.
        if rng.below(15) == 0 || round + 1 == rounds {
            follow(&primary, &replica);
            assert_eq!(replica.position(), primary.position());
            for (id, path) in &pages {
                let ours = primary.content().get(*id).unwrap();
                let theirs = replica.content().get(*id).unwrap();
                assert_eq!(
                    ours.as_ref().map(|e| (e.revision(), e.field("n").cloned())),
                    theirs
                        .as_ref()
                        .map(|e| (e.revision(), e.field("n").cloned())),
                    "round {round}, entity {id}"
                );
                assert_eq!(
                    primary
                        .content()
                        .resolve(nex_db::DEFAULT_SITE, path)
                        .unwrap()
                        .map(|r| r.entity()),
                    replica
                        .content()
                        .resolve(nex_db::DEFAULT_SITE, path)
                        .unwrap()
                        .map(|r| r.entity()),
                    "round {round}, path {path}"
                );
            }
            for token in &tokens {
                assert_eq!(
                    primary
                        .auth()
                        .validate(token)
                        .unwrap()
                        .session()
                        .map(|s| s.account()),
                    replica
                        .auth()
                        .validate(token)
                        .unwrap()
                        .session()
                        .map(|s| s.account()),
                    "round {round}"
                );
            }
            checked += 1;
        }
    }
    assert!(checked >= 2);
}
