//! Detects whether the compiler offers `std::fs::File::try_lock` (Rust 1.89),
//! which nex-db uses to give one process ownership of a database directory.
//! Older compilers (down to the 1.85 MSRV) use a fallback; see
//! `src/core/fs.rs`.

use std::{env, process::Command};

fn main() {
    println!("cargo::rustc-check-cfg=cfg(nex_file_lock)");
    println!("cargo::rustc-check-cfg=cfg(nex_loom)");
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=RUSTC");
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let minor = Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|text| {
            let version = text.split_whitespace().nth(1)?.to_owned();
            version.split('.').nth(1)?.parse::<u32>().ok()
        });
    if minor.is_some_and(|m| m >= 89) {
        println!("cargo::rustc-cfg=nex_file_lock");
    }
}
