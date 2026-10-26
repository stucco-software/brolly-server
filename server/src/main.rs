//! HTTP service entrypoint.

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Before anything can build a reqwest client: with `rustls-no-provider`,
    // building one without a provider panics. It comes before logging too,
    // so no future edit can add a client above it.
    brolly_server::tls::install_crypto_provider();

    // Structured logging from the first line. No `println!` anywhere in the
    // workspace — the lint denies it (implementation plan §5).
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Absent unless asked for, so a local instance does not try to publish
    // test identities to the real PLC directory. Built here, before the
    // database, so a host with no CA bundle fails at once with a clear error
    // and a non-zero exit, not a panic after migrations have run.
    let plc_client = if std::env::var("BROLLY_PLC_SUBMIT").is_ok_and(|v| v == "1" || v == "true") {
        match brolly_server::tls::https_client() {
            Ok(client) => Some(client),
            Err(e) => {
                tracing::error!(error = %e, "BROLLY_PLC_SUBMIT is set but the HTTPS client cannot be built");
                return Err(e.into());
            }
        }
    } else {
        None
    };

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

    // An instance with no accounts has no way to make one: registration needs
    // an invite and invites need an admin. This breaks that cycle, and is a
    // no-op on every start after the first person registers.
    brolly_server::admin::bootstrap(&pool).await?;

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

    // The instance is an agent (D4): it owns the shared inbox and the
    // cross-user index, and it signs its own outbound delivery. Created on
    // first start and never regenerated — the public key is published in the
    // actor document and cached by every instance that has seen us.
    let instance_actor =
        brolly_identity::instance::load_or_create(&pool, brolly_activitypub::keys::generate)
            .await?;

    let base_domain =
        std::env::var("BROLLY_BASE_DOMAIN").unwrap_or_else(|_| "brolly.test".to_string());

    // The one upload limit (spec 4, H3): read here, with the rest of the env
    // config, before the state is built — the router's `DefaultBodyLimit` is
    // wired from it at composition. Defaults to the same constant the
    // instance configuration advertises, so an operator who sets nothing gets
    // a limit that matches the advertisement.
    let max_upload_bytes = std::env::var("BROLLY_MAX_UPLOAD_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(brolly_domain::media::MAX_UPLOAD_BYTES);
    // And the pod's quota, the same way.
    let pod_quota_bytes = std::env::var("BROLLY_POD_QUOTA_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(brolly_domain::media::DEFAULT_POD_QUOTA_BYTES);

    let state = brolly_server::AppState {
        limiter: std::sync::Arc::new(brolly_server::ratelimit::Limiter::new()),
        pool,
        base_domain: base_domain.clone(),
        // Falls back to the domain rather than to a brand: an operator who
        // never sets this gets an instance that names itself honestly.
        instance_name: std::env::var("BROLLY_INSTANCE_NAME")
            .ok()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or(base_domain),
        instance_description: std::env::var("BROLLY_INSTANCE_DESCRIPTION")
            .ok()
            .filter(|d| !d.trim().is_empty())
            .unwrap_or_else(|| "A private community server.".to_string()),
        source_url: std::env::var("BROLLY_SOURCE_URL")
            .unwrap_or_else(|_| brolly_server::SOURCE_URL_DEFAULT.to_string()),
        terms_url: std::env::var("BROLLY_TERMS_URL")
            .ok()
            .filter(|s| !s.is_empty()),
        privacy_url: std::env::var("BROLLY_PRIVACY_URL")
            .ok()
            .filter(|s| !s.is_empty()),
        // Off by default: an open registration door is a public deployment's
        // decision, not a private community's default. Read here with the rest
        // of the door's config; the form and the account-creation API both
        // read it from the state.
        public_registration: std::env::var("BROLLY_PUBLIC_REGISTRATION")
            .is_ok_and(|v| v == "1" || v == "true"),
        // `www` points wherever the deployment says, or nowhere. Validated
        // here rather than in the middleware so a typo is a startup failure
        // with the offending value in the log, not a 500 on every request to
        // the host.
        www_redirect: match std::env::var("BROLLY_WWW_REDIRECT") {
            Ok(value) => match brolly_server::parse_www_redirect(&value) {
                Ok(base) => Some(base),
                Err(reason) => {
                    tracing::error!(
                        value = %value,
                        reason = %reason,
                        "BROLLY_WWW_REDIRECT is not a usable redirect base"
                    );
                    return Err(reason.into());
                }
            },
            Err(_) => None,
        },
        max_upload_bytes,
        pod_quota_bytes,
        stores: std::sync::Arc::new(stores),
        provider_key: std::sync::Arc::new(provider_key),
        instance_actor: std::sync::Arc::new(instance_actor),
        commits: tokio::sync::broadcast::channel(
            // Bounded: a consumer that falls this far behind is dropped and
            // reconnects with its cursor, which is cheaper than letting one
            // slow reader grow the buffer without limit.
            1024,
        )
        .0,
        plc_client,
        // ATProto OAuth clients are identified by a URL serving their
        // metadata. Fetched from public addresses only, validated, cached.
        clients: std::sync::Arc::new(brolly_server::client_metadata::Fetcher::<
            brolly_atproto::client_metadata::ClientMetadata,
        >::new()?),
        // Solid-OIDC clients with a Client ID Document are identified by the
        // document itself (spec 6, H3): the same hardened transport, asking
        // for RDF instead of JSON.
        solid_clients: std::sync::Arc::new(brolly_server::client_metadata::Fetcher::<
            brolly_solid::client_documents::ClientIdDocument,
        >::new()?),
        // A foreign Solid-OIDC issuer's discovery document and key set
        // (spec 6, H5): the same transport again, asking for JSON, cached
        // per issuer — the remote path a token whose `iss` is not ours takes.
        issuer_discovery: std::sync::Arc::new(brolly_server::client_metadata::Fetcher::<
            brolly_solid::oidc::tokens::RemoteDiscovery,
        >::new()?),
        issuer_jwks: std::sync::Arc::new(brolly_server::client_metadata::Fetcher::<
            brolly_solid::oidc::tokens::RemoteJwks,
        >::new()?),
        // A remote WebID's profile document (spec 6, H5): the dereference
        // the issuer binding reads, asking for RDF like the Client ID
        // Document fetch, cached per WebID.
        webid_documents: std::sync::Arc::new(brolly_server::client_metadata::Fetcher::<
            brolly_solid::webid_documents::WebIdDocument,
        >::new()?),
    };

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, static_dir, "brolly-server listening");

    // The shared firehose listener (1, G): one dedicated connection, taken
    // from the pool and held for the process's lifetime, turning any
    // process's committed events into this process's broadcasts. Spawned
    // before the server accepts connections, so no subscriber can attach
    // before the listener does.
    tokio::spawn(brolly_atproto::firehose::listen(
        state.pool.clone(),
        state.commits.clone(),
    ));

    // With the peer address, so the rate limits have a key when no proxy is
    // in front of the deployment to report one.
    axum::serve(
        listener,
        brolly_server::app(state, &static_dir)
            .into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
