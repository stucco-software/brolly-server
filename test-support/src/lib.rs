//! Test fixtures and container provisioning.
//!
//! `cargo test` provisions its own Postgres through testcontainers, so a clean
//! clone needs no environment setup and **no test is `#[ignore]`d**. A test that
//! only runs when someone remembers to set an env var eventually stops passing
//! — the previous codebase had 228 such tests.
//!
//! Requires a running Docker daemon. That is the one prerequisite, and it is
//! checked loudly rather than skipped silently.

// This crate is dev-only. A fixture that cannot start should abort loudly with a
// useful message rather than thread `Result` through every test signature.
#![allow(clippy::expect_used)]

use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

/// A throwaway Postgres instance plus a connected pool.
///
/// The container is torn down when this value is dropped, so bind it to a
/// variable that lives as long as the test.
pub struct TestDb {
    _container: ContainerAsync<Postgres>,
    pub pool: PgPool,
    /// The connection string, for tests that spawn a subprocess rather than
    /// using the pool. `brolly-admin` connects with `DATABASE_URL`.
    pub url: String,
}

/// Start a Postgres container and connect to it.
///
/// Panics with an actionable message if Docker is unavailable — that is a
/// broken environment, not a reason to skip the test.
pub async fn postgres() -> TestDb {
    let container = Postgres::default()
        .start()
        .await
        .expect("start postgres container (is the Docker daemon running?)");

    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("map postgres port");

    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let pool = PgPool::connect(&url)
        .await
        .expect("connect to test postgres");

    TestDb {
        _container: container,
        pool,
        url,
    }
}
