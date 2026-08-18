# brolly-server

A multi-protocol identity-and-data server: a **Solid** pod, an **ATProtocol**
PDS, an **ActivityPub** server, and a **Mastodon** client API — all reading and
writing the same per-user RDF store.

- **What we're building and in what order:** [`docs/greenfield-implementation-plan.md`](docs/greenfield-implementation-plan.md)
- **Why it's shaped this way:** [`docs/greenfield-learnings.md`](docs/greenfield-learnings.md) — a retrospective on the predecessor
- **Decisions:** plan §1 (D1–D16), plus [`docs/architecture/adr/`](docs/architecture/adr/)

## Licence

**AGPL-3.0-or-later.** brolly is intended as a public good: if you run a modified
copy, the network clause means you owe your users the source. See
[`docs/architecture/adr/0003-activitypub-federation-licence.md`](docs/architecture/adr/0003-activitypub-federation-licence.md).

## Status

**Phase 0 — Foundations.** The workspace, the crate graph, the lint and test
gates, and the design-system seed are in place. No protocol is implemented yet.

## Development setup

```bash
rustup install stable
rustup component add rustfmt clippy
cargo install cargo-deny --locked
cargo install lefthook --locked && lefthook install   # pre-commit gates
```

**Docker must be running.** Integration tests provision their own Postgres via
testcontainers, which is why nothing is `#[ignore]`d and why a clean clone needs
no other environment setup.

## Running

```bash
cargo run -p brolly-server
# → http://localhost:3000
```

`BROLLY_PORT` and `BROLLY_STATIC_DIR` override the defaults. `RUST_LOG` controls
the tracing filter.

## Gates

Everything below runs in CI on every push, and the first three run pre-commit:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
./tools/check-doc-paths.sh
```

## The rules that are tests, not conventions

The predecessor lost these to drift, so they're enforced mechanically:

| Rule | Enforced by |
|---|---|
| `app()` exists only in `brolly-server` | `server/tests/architecture.rs` |
| Adapters never depend on each other | `server/tests/architecture.rs` |
| `brolly-domain` has no internal dependencies | `server/tests/architecture.rs` |
| No `println!`/`eprintln!`/`dbg!` in libraries | workspace clippy lints (deny) |
| No `unwrap`/`expect`/`panic!` in libraries | workspace clippy lints (deny) |
| HTML is never built with `format!` | `server/tests/ui_invariants.rs` |
| One stylesheet, one token source | `server/tests/ui_invariants.rs` |
| No literal colors outside the token layer | `server/tests/ui_invariants.rs` |
| Every page has one `h1`, a `<main>`, and a skip link | `server/tests/ui_invariants.rs` |
| Doc paths resolve | `tools/check-doc-paths.sh` |

## Layout

```
domain/       canonical vocabulary, quad model, projections. Zero deps, zero I/O.
store/        per-user pod stores + the server-agent store.
authz/        Web Access Control, evaluated as SPARQL on every read.
identity/     users, WebID, DIDs, keys, sessions, Subject.
adapters/     solid · atproto · activitypub · mastodon — siblings, never coupled.
server/       composes adapters, owns app(), serves HTTP.
test-support/ container provisioning and fixtures.
```
