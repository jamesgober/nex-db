// The table benchmark includes the table with `cfg(test)` set but no test
// harness, which drops every test and leaves these imports unused.
#![allow(unused_imports)]

use super::*;

#[cfg(not(all(nex_loom, test)))]
mod plain {
    use std::collections::HashMap;

    use super::*;

    /// A key whose hash bytes are `n` spread by a fixed mix, like a MAC.
    fn key(n: u64) -> [u8; 32] {
        let mut x = n.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut k = [0; 32];
        for chunk in k.chunks_exact_mut(8) {
            x ^= x >> 30;
            x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
            x ^= x >> 27;
            x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
            x ^= x >> 31;
            chunk.copy_from_slice(&x.to_le_bytes());
        }
        k
    }

    fn words(n: u64) -> [u64; 3] {
        [n, n + 1, n + 2]
    }

    #[test]
    fn test_match_bytes_find_only_their_bytes() {
        let group = u64::from_le_bytes([0x12, EMPTY, 0x12, DELETED, 0x05, 0x7F, EMPTY, 0x00]);
        assert_eq!(match_byte(group, 0x12) & HI, (1 << 7) | (1 << 23));
        assert_eq!(match_empty(group), (1 << 15) | (1 << 55));
        assert_eq!(match_free(group), (1 << 15) | (1 << 31) | (1 << 55));
        assert_eq!(with_byte(group, 0, 0x33).to_le_bytes()[0], 0x33);
    }

    #[test]
    fn test_insert_get_update_remove() {
        let table: Table<3, 2> = Table::new(4, 8, 1000);
        let at = table.insert(&key(1), &words(1), None, 9).unwrap();
        let found = table.get(&key(1)).unwrap();
        assert_eq!(found.at, at);
        assert_eq!(found.words, words(1));
        assert_eq!(found.ext, None);
        assert_eq!(found.aux, 9);
        assert_eq!(
            table.insert(&key(1), &words(2), None, 0),
            Err(Refused::Exists(at))
        );
        assert!(table.get(&key(2)).is_none());

        assert!(table.update(at, &words(5), Some(&[7, 8])));
        let found = table.get(&key(1)).unwrap();
        assert_eq!(found.words, words(5));
        assert_eq!(found.ext, Some([7, 8]));
        assert_eq!(found.aux, 9);
        table.raise_aux(at, 4);
        table.raise_aux(at, 12);
        assert_eq!(table.get(&key(1)).unwrap().aux, 12);
        assert!(table.update(at, &words(6), None));
        assert_eq!(table.get(&key(1)).unwrap().ext, None);

        assert_eq!(table.len(), 1);
        assert!(table.remove(at));
        assert!(!table.remove(at));
        assert!(!table.update(at, &words(1), None));
        assert!(table.get(&key(1)).is_none());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_many_entries_match_a_map_through_growth_and_churn() {
        let table: Table<3, 2> = Table::new(4, 8, 20_000);
        let mut model: HashMap<u64, At> = HashMap::new();
        for n in 0..10_000u64 {
            let ext = (n % 3 == 0).then_some([n, !n]);
            let at = table.insert(&key(n), &words(n), ext.as_ref(), n).unwrap();
            let _ = model.insert(n, at);
        }
        assert!(
            table
                .shards
                .iter()
                .any(|s| s.state.load(Ordering::Relaxed) & 0xFF > 0)
        );
        // Remove two thirds, then insert as many new ones.
        for n in (0..10_000u64).filter(|n| n % 3 != 1) {
            assert!(table.remove(model.remove(&n).unwrap()));
        }
        for n in 10_000..16_000u64 {
            let at = table.insert(&key(n), &words(n), None, n).unwrap();
            let _ = model.insert(n, at);
        }
        assert_eq!(table.len(), model.len());
        for n in 0..16_000u64 {
            match (table.get(&key(n)), model.get(&n)) {
                (Some(found), Some(at)) => {
                    assert_eq!(found.at, *at);
                    assert_eq!(found.words, words(n));
                    assert_eq!(found.ext, (n % 3 == 0 && n < 10_000).then_some([n, !n]));
                }
                (None, None) => {}
                (found, at) => panic!("key {n}: table {found:?}, model {at:?}"),
            }
        }
        let mut all = Vec::new();
        table.for_each(|k, found| all.push((k, found.at)));
        assert_eq!(all.len(), model.len());
        for (k, at) in all {
            assert_eq!(table.read_at(at).map(|(key, _)| key), Some(k));
        }
    }

    #[test]
    fn test_churn_reuses_cells_and_keeps_the_index_small() {
        let table: Table<3, 0> = Table::new(1, 8, 100_000);
        let mut live: Vec<(u64, At)> = Vec::new();
        for n in 0..200_000u64 {
            let at = table.insert(&key(n), &words(n), None, 0).unwrap();
            live.push((n, at));
            if live.len() > 50 {
                let (_, at) = live.remove(0);
                assert!(table.remove(at));
            }
        }
        let shard = &table.shards[0];
        let w = shard.writer.lock().unwrap();
        // Cells come back from the free list; tombstones go at rebuilds.
        assert!(w.next <= 51);
        assert!(w.class <= 5, "class {}", w.class);
        drop(w);
        for (n, _) in &live {
            assert_eq!(table.get(&key(*n)).unwrap().words, words(*n));
        }
        assert!(table.get(&key(0)).is_none());
    }

    #[test]
    fn test_readers_never_miss_a_present_key_across_rebuilds() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        let table: Arc<Table<1, 0>> = Arc::new(Table::new(1, 8, 200_000));
        for n in 0..32u64 {
            let _ = table.insert(&key(n), &[n], None, 0).unwrap();
        }
        let stop = Arc::new(AtomicBool::new(false));
        let readers: Vec<_> = (0..3)
            .map(|_| {
                let table = Arc::clone(&table);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    let mut reads = 0u64;
                    while !stop.load(Ordering::Relaxed) || reads < 10_000 {
                        let n = reads % 32;
                        assert_eq!(table.get(&key(n)).map(|f| f.words), Some([n]));
                        reads += 1;
                    }
                })
            })
            .collect();
        // Growth, then churn that leaves tombstones, each forcing rebuilds.
        let mut ats = Vec::new();
        for n in 1_000..60_000u64 {
            ats.push(table.insert(&key(n), &[n], None, 0).unwrap());
        }
        for at in ats.drain(..) {
            assert!(table.remove(at));
        }
        for n in 100_000..160_000u64 {
            let at = table.insert(&key(n), &[n], None, 0).unwrap();
            if n % 2 == 0 {
                assert!(table.remove(at));
            }
        }
        stop.store(true, Ordering::Relaxed);
        for r in readers {
            r.join().unwrap();
        }
    }

    #[test]
    fn test_full_table_refuses() {
        let table: Table<1, 0> = Table::new(1, 8, 8);
        let mut n = 0u64;
        let refused = loop {
            match table.insert(&key(n), &[n], None, 0) {
                Ok(_) => n += 1,
                Err(e) => break e,
            }
        };
        assert_eq!(refused, Refused::Full);
        assert!(n >= 16);
        for m in 0..n {
            assert_eq!(table.get(&key(m)).unwrap().words, [m]);
        }
    }

    #[test]
    fn test_readers_never_see_a_torn_entry() {
        use std::sync::Arc;
        let table: Arc<Table<4, 4>> = Arc::new(Table::new(1, 8, 64));
        let at = table.insert(&key(1), &[0; 4], Some(&[0; 4]), 0).unwrap();
        let reader = {
            let table = Arc::clone(&table);
            std::thread::spawn(move || {
                let mut reads = 0u64;
                while reads < 200_000 {
                    if let Some(found) = table.get(&key(1)) {
                        let v = found.words[0];
                        assert!(found.words.iter().all(|w| *w == v));
                        if let Some(ext) = found.ext {
                            assert!(ext.iter().all(|w| *w == v));
                        }
                        reads += 1;
                    }
                }
            })
        };
        for v in 1..50_000u64 {
            let ext = (v % 2 == 0).then_some([v; 4]);
            assert!(table.update(at, &[v; 4], ext.as_ref()));
        }
        reader.join().unwrap();
    }

    #[test]
    fn test_chunks_cover_every_item_once() {
        let mut expect = (0, 0);
        for n in 0..(GROWING + 3 * LAST_CHUNK) {
            assert_eq!(chunk_of(n), expect, "item {n}");
            expect.1 += 1;
            if expect.1 == chunk_len(expect.0) {
                expect = (expect.0 + 1, 0);
            }
            assert_eq!(chunks_for(n + 1), chunk_of(n).0 + 1);
        }
        assert_eq!(chunks_for(0), 0);
    }

    #[test]
    fn test_at_round_trips_through_u64() {
        let at = At {
            shard: 63,
            index: u32::MAX,
        };
        assert_eq!(At::from_u64(at.to_u64()), at);
    }
}

/// Models of the slot protocol under every interleaving loom explores. Run
/// with `RUSTFLAGS="--cfg nex_loom" cargo test --release --lib loom`.
#[cfg(all(nex_loom, test))]
mod models {
    use loom::sync::Arc;

    use super::*;

    fn key(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn loom_reader_sees_old_or_new_words_never_a_mix() {
        loom::model(|| {
            let table: Arc<Table<2, 2>> = Arc::new(Table::new(1, 8, 8));
            let at = table.insert(&key(1), &[1, 1], Some(&[1, 1]), 0).unwrap();
            let reader = {
                let table = Arc::clone(&table);
                loom::thread::spawn(move || {
                    let found = table.get(&key(1)).unwrap();
                    let v = found.words[0];
                    assert!(v == 1 || v == 2);
                    assert_eq!(found.words, [v, v]);
                    assert_eq!(found.ext, Some([v, v]));
                })
            };
            assert!(table.update(at, &[2, 2], Some(&[2, 2])));
            reader.join().unwrap();
        });
    }

    #[test]
    fn loom_insert_is_seen_whole_or_not_at_all() {
        loom::model(|| {
            let table: Arc<Table<2, 0>> = Arc::new(Table::new(1, 8, 8));
            let reader = {
                let table = Arc::clone(&table);
                loom::thread::spawn(move || {
                    if let Some(found) = table.get(&key(3)) {
                        assert_eq!(found.words, [3, 4]);
                    }
                })
            };
            let _ = table.insert(&key(3), &[3, 4], None, 0).unwrap();
            reader.join().unwrap();
            assert_eq!(table.get(&key(3)).unwrap().words, [3, 4]);
        });
    }

    #[test]
    fn loom_remove_is_seen_as_gone_or_whole() {
        loom::model(|| {
            let table: Arc<Table<2, 0>> = Arc::new(Table::new(1, 8, 8));
            let at = table.insert(&key(5), &[5, 6], None, 0).unwrap();
            let reader = {
                let table = Arc::clone(&table);
                loom::thread::spawn(move || {
                    if let Some(found) = table.get(&key(5)) {
                        assert_eq!(found.words, [5, 6]);
                    }
                })
            };
            assert!(table.remove(at));
            reader.join().unwrap();
            assert!(table.get(&key(5)).is_none());
        });
    }
}
