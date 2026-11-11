//! Every decoder of data that comes from outside the process: files on
//! disk, log records, the split-auth channel, tokens, and passkey replies.
//! Built only for fuzzing (`cargo fuzz`, which sets `--cfg fuzzing`) and for
//! the tests below; not part of the API.
//!
//! A target gets arbitrary bytes. It may return an error; it must not
//! panic, hang, or allocate more than the input justifies.

/// A decoder and its name.
pub type Target = (&'static str, fn(&[u8]));

/// The decoders, by name.
pub fn targets() -> Vec<Target> {
    #[allow(unused_mut)]
    let mut targets: Vec<Target> = vec![
        ("record", crate::core::record::fuzz),
        ("catalog", crate::core::catalog::fuzz),
        ("root_key", crate::core::keys::fuzz),
        ("backup", crate::backup::fuzz),
    ];
    #[cfg(feature = "content")]
    targets.push(("content", crate::content::fuzz));
    #[cfg(feature = "auth")]
    targets.push(("auth", crate::auth::fuzz));
    targets
}

/// One fuzz input: its first byte picks the target, the rest is the data.
pub fn run(data: &[u8]) {
    let Some((pick, rest)) = data.split_first() else {
        return;
    };
    let targets = targets();
    if let Some((_, target)) = targets.get(usize::from(*pick) % targets.len()) {
        target(rest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small deterministic generator (splitmix64).
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n.max(1)
        }

        /// Bytes that often pass length checks: mostly small values, some
        /// all-ones, some random.
        fn bytes(&mut self, len: usize) -> Vec<u8> {
            (0..len)
                .map(|_| match self.below(8) {
                    0..=3 => self.below(4) as u8,
                    4 => 0xFF,
                    _ => self.next() as u8,
                })
                .collect()
        }

        /// `seed` with a few bytes changed, cut, or added.
        fn mutate(&mut self, seed: &[u8]) -> Vec<u8> {
            let mut out = seed.to_vec();
            for _ in 0..=self.below(4) {
                match self.below(4) {
                    0 if !out.is_empty() => {
                        let i = self.below(out.len() as u64) as usize;
                        out[i] ^= 1 << self.below(8);
                    }
                    1 if !out.is_empty() => {
                        let len = self.below(out.len() as u64) as usize;
                        out.truncate(len);
                    }
                    2 => {
                        let len = self.below(16) as usize;
                        let extra = self.bytes(len);
                        out.extend(extra);
                    }
                    _ if !out.is_empty() => {
                        let i = self.below(out.len() as u64) as usize;
                        out[i] = [0, 1, 0x7F, 0x80, 0xFF][self.below(5) as usize];
                    }
                    _ => {}
                }
            }
            out
        }
    }

    /// Valid encodings to mutate, so inputs get past the first checks.
    fn seeds() -> Vec<Vec<u8>> {
        #[allow(unused_mut)]
        let mut seeds = vec![Vec::new(), vec![0; 64], vec![0xFF; 64]];
        #[cfg(feature = "content")]
        {
            use crate::{
                content::{
                    entity::{Body, Entity, Revision, encode_route},
                    locale::Locale,
                },
                ids::EntityId,
            };
            let head = Entity::new("page")
                .field("title", "Hello")
                .field("n", 7_i64)
                .path("/hello")
                .into_head(EntityId::from_bytes([3; 16]), 1, Locale::EN)
                .unwrap();
            seeds.push(head.encode().unwrap());
            let revision = Revision::new(
                Locale::EN,
                1,
                "first",
                Body {
                    path: Some("/hello".into()),
                    fields: head.base().draft.fields.clone(),
                },
            )
            .unwrap();
            seeds.push(revision.encode().unwrap());
            seeds.push(encode_route(&crate::content::entity::RouteEntry {
                entity: head.rid,
                revision: 1,
                kind: crate::content::entity::RouteKind::Page,
                visibility: head.visibility,
                locale: Locale::EN,
                canary: false,
            }));
        }
        #[cfg(feature = "auth")]
        {
            let (token, _) = crate::auth::token::Token::generate().unwrap();
            seeds.push(token.as_str().as_bytes().to_vec());
        }
        seeds
    }

    #[test]
    fn test_no_decoder_panics_on_arbitrary_or_mutated_input() {
        let mut rng = Rng(0x5EED);
        let seeds = seeds();
        let rounds = std::env::var("NEX_FUZZ_ROUNDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3_000u64);
        for (name, target) in targets() {
            for round in 0..rounds {
                let data = if round % 2 == 0 {
                    let len = rng.below(300) as usize;
                    rng.bytes(len)
                } else {
                    let seed = &seeds[rng.below(seeds.len() as u64) as usize];
                    rng.mutate(seed)
                };
                let outcome = std::panic::catch_unwind(|| target(&data));
                assert!(outcome.is_ok(), "{name} panicked on {data:02x?}");
            }
        }
    }

    #[test]
    fn test_run_picks_every_target() {
        let targets = targets();
        for pick in 0..targets.len() as u8 {
            run(&[pick, 1, 2, 3]);
        }
        run(&[]);
    }
}
