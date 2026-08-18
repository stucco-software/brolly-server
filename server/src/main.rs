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

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, static_dir, "brolly-server listening");

    axum::serve(listener, brolly_server::app(&static_dir)).await?;
    Ok(())
}
