//! HTTP service entrypoint.

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Structured logging from the first line. No `println!` anywhere in the
    // workspace — the lint denies it (implementation plan §5).
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let static_dir =
        std::env::var("BROLLY_STATIC_DIR").unwrap_or_else(|_| "server/static".to_string());
    let port: u16 = std::env::var("BROLLY_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost/brolly".to_string());
    let pool = sqlx::PgPool::connect(&database_url).await?;
    brolly_identity::db::MIGRATOR.run(&pool).await?;

    let data_dir = std::env::var("BROLLY_DATA_DIR").unwrap_or_else(|_| "data".to_string());
    let stores = brolly_store::StoreManager::open(
        &data_dir,
        // Working-set estimate, to be revised from a hit-rate metric — an LRU
        // miss costs ~8ms against ~0.5us for a hit (ADR 0006).
        500, 3600,
    )?;

    // Loaded once, not per request: it signs and verifies on every token
    // operation. Generated on first start and reused forever after — rotating
    // it would invalidate every live access token.
    let provider_key = brolly_solid::oidc::store::load_or_create_key(&pool).await?;

    let state = brolly_server::AppState {
        pool,
        base_domain: std::env::var("BROLLY_BASE_DOMAIN")
            .unwrap_or_else(|_| "brolly.test".to_string()),
        stores: std::sync::Arc::new(stores),
        provider_key: std::sync::Arc::new(provider_key),
    };

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, static_dir, "brolly-server listening");

    axum::serve(listener, brolly_server::app(state, &static_dir)).await?;
    Ok(())
}
