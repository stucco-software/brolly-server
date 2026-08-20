//! Force re-expansion of `sqlx::migrate!()` when a migration is added.
//!
//! The macro embeds the migrations directory at compile time. Without this,
//! adding a file leaves a stale expansion and tests fail with
//! `Migrate(VersionMissing(...))` — the predecessor's workaround was to
//! remember to touch a source file.
fn main() {
    println!("cargo:rerun-if-changed=../migrations");
}
