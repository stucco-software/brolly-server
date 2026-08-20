# Migrations

One directory. `sqlx-cli` runs them in filename order and `_sqlx_migrations`
tracks what applied.

## Ownership by filename prefix

| Prefix | Owning crate |
|---|---|
| `identity_*` | `brolly-identity` |
| `solid_*` | `brolly-solid` |
| `atproto_*` | `brolly-atproto` |
| `ap_*` | `brolly-activitypub` |
| `mastodon_*` | `brolly-mastodon` |

## Rules

1. **One directory.** Per-crate `migrations/` directories break `sqlx-cli`,
   which assumes one path, and fragment the history table.
2. **Prefix by owning crate**, so a reviewer can grep the diff.
3. **One concern per migration.** No cross-crate bundling.
4. **Forward-only.** To undo a table, write a `*_drop_*.sql` follow-up.
5. **No user content.** Postgres holds operational state only (D2/D5); content
   lives in pods. The predecessor drifted from this four times in one week and
   once more seven weeks later.

## The staleness gotcha, and why it is handled

`sqlx::migrate!()` is a proc macro that embeds the directory at compile time.
Adding a file without touching any Rust source leaves the expansion stale, and
tests fail with `Migrate(VersionMissing(...))`. The predecessor's fix was to
remember to `touch src/db.rs`.

`identity/build.rs` emits `cargo:rerun-if-changed=migrations`, so cargo
re-expands automatically. Do not remove it.
