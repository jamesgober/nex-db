<h1 align="center">
    <b>nex-db</b>
    <br>
    <sub><sup>EMBEDDED DATABASE</sup></sub>
</h1>

<div align="center">
    <a href="https://github.com/jamesgober/nex-db/actions"><img alt="CI" src="https://github.com/jamesgober/nex-db/actions/workflows/ci.yml/badge.svg"></a>
</div>

<br>

**nex-db** is an embedded database for Rust. Engines run side by side on one core: one commit log, one catalog, and one read snapshot shared by every engine, so a commit that touches several engines is atomic. Every operation is typed; there is no query string to build or inject.

The first engines are an auth engine (sessions, credentials, tokens, roles), kept sealed under its own keys and files, and a content engine (pages, translations, routes).

MSRV is 1.85 (Rust 2024 edition). `#![forbid(unsafe_code)]`.

## Status

Scaffold. No functional code yet. The plan is in [`dev/PLAN.md`](./dev/PLAN.md) and the schedule in [`dev/ROADMAP.md`](./dev/ROADMAP.md).

## License

Licensed under either of

- Apache License, Version 2.0: [LICENSE-APACHE](./LICENSE-APACHE)
- MIT License: [LICENSE-MIT](./LICENSE-MIT)

at your option.

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
