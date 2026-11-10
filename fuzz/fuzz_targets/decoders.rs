//! Every decoder of outside data: the first byte picks one, the rest is its
//! input (`nex_db::fuzz::run`).

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    nex_db::fuzz::run(data);
});
