//! Benchmarks of the session table's fixed-key table on its own, at sizes
//! the auth engine's own benchmark does not build through commits.
//!
//! ```text
//! cargo bench --bench table
//! NEX_BENCH_LARGE=1 cargo bench --bench table   # also 10 and 100 million
//! ```

#[path = "../src/table/mod.rs"]
mod table;

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use table::Table;

/// Slot words and extension words as the session table uses them.
type Sessions = Table<14, 25>;

/// A key spread like a MAC output.
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

fn get_hit(c: &mut Criterion) {
    let mut sizes = vec![1_000_000u64];
    if std::env::var_os("NEX_BENCH_LARGE").is_some() {
        sizes.extend([10_000_000, 100_000_000]);
    }
    for n in sizes {
        let table = Sessions::new(16, 512, n as usize);
        for i in 0..n {
            let _ = table.insert(&key(i), &[i; 14], None, i).unwrap();
        }
        // Memory per entry, slots and control bytes included.
        eprintln!(
            "table/memory: {n} entries, {} bytes each",
            table.memory() / n as usize
        );
        // Up to a million keys spread over the whole table, old and new.
        let sample = n.min(1 << 20);
        let keys: Vec<[u8; 32]> = (0..sample).map(|j| key(j * (n / sample))).collect();
        let misses: Vec<[u8; 32]> = (0..sample).map(|j| key(n + j)).collect();
        let mut i = 0usize;
        let mut group = c.benchmark_group("table/get_hit");
        let _ = group.bench_function(format!("{n}"), |b| {
            b.iter(|| {
                i = (i + 7_919) % keys.len();
                black_box(table.get(black_box(&keys[i])))
            });
        });
        group.finish();
        let mut group = c.benchmark_group("table/get_miss");
        let _ = group.bench_function(format!("{n}"), |b| {
            b.iter(|| {
                i = (i + 7_919) % misses.len();
                black_box(table.get(black_box(&misses[i])))
            });
        });
        group.finish();
    }
}

criterion_group!(benches, get_hit);
criterion_main!(benches);
