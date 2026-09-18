//! Outbound TLS.
//!
//! reqwest is built with `rustls-no-provider`, the only TLS option it has that
//! avoids aws-lc-rs. That means no rustls crypto provider is chosen at compile
//! time, and building a `reqwest::Client` **panics** until one is installed.
//! [`install_crypto_provider`] installs ring. Both binaries call it as their
//! first statement, and so does every test that builds a client.
//!
//! Root certificates come from `rustls-platform-verifier`, which reads the OS
//! store. On Linux it reads it when the client is *built*, and fails the build
//! if the store is empty, so [`https_client`] returns that as an error rather
//! than panicking. The runtime image installs `ca-certificates` (`Dockerfile`).

/// Install ring as the process-wide rustls crypto provider.
///
/// Idempotent. rustls allows exactly one install per process and reports a
/// second one as an error. That error is ignored: ring is the only provider
/// compiled into this binary, so "already installed" can only mean "already
/// installed by us". Tests call this from many threads in one process, so
/// the second call being harmless is required, not just convenient.
pub fn install_crypto_provider() {
    let _already_installed = rustls::crypto::ring::default_provider().install_default();
}

/// Build the outbound HTTPS client. Call [`install_crypto_provider`] first:
/// without a provider this panics inside reqwest.
///
/// `Client::builder().build()`, not `Client::new()`. On Linux, building
/// constructs rustls-platform-verifier, which loads the OS root store there
/// and then fails with "No CA certificates were loaded from the system" if
/// the host has no CA bundle. `Client::new()` would turn that into a panic.
/// It's a deployment mistake, so the binaries report it and exit non-zero.
///
/// The error is the whole source chain on one line. reqwest's own `Display`
/// for a builder error is just "builder error", and the cause is the part an
/// operator needs.
pub fn https_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder().build().map_err(|e| {
        let mut message = format!("cannot build the outbound HTTPS client: {e}");
        let mut source = std::error::Error::source(&e);
        while let Some(cause) = source {
            message.push_str(": ");
            message.push_str(&cause.to_string());
            source = cause.source();
        }
        message.push_str(" (is the OS CA bundle, e.g. `ca-certificates`, installed?)");
        message
    })
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::sync::Arc;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    use super::*;

    /// A CA, and a certificate for `localhost` it signed.
    struct Pki {
        ca: CertificateDer<'static>,
        leaf: CertificateDer<'static>,
        leaf_key: PrivateKeyDer<'static>,
    }

    /// Generated per run: a committed fixture would expire, and then the test
    /// would fail for reasons unrelated to what it checks.
    ///
    /// `ca_name` becomes the CA's common name, and so the leaf's issuer name.
    /// Every CA needs its own. rcgen's default DN is the same for every
    /// certificate ("rcgen self signed cert"), and webpki picks candidate
    /// issuers by name. Two CAs with the same name would make the refusal test
    /// fail with `BadSignature` (right name, wrong key) instead of
    /// `UnknownIssuer`, which is not the case it means to check.
    fn pki(ca_name: &str) -> Pki {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, ca_name);
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let mut leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();

        Pki {
            ca: ca.der().clone(),
            leaf: leaf.der().clone(),
            leaf_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        }
    }

    /// Answer one HTTPS request with `200 ok`, on its own thread. Returns the
    /// address it listens on.
    ///
    /// Plain blocking rustls rather than tokio-rustls, so it needs no dependency
    /// beyond the one the server already has. The server uses its own explicit
    /// provider, so it can't be what makes the client side work.
    fn serve_once(leaf: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> SocketAddr {
        let config = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf], key)
            .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        std::thread::spawn(move || {
            // No unwraps in here. A refused handshake is the expected outcome
            // of one test and shows up as a read error. The thread just ends,
            // and the assertion that matters is on the client's side.
            let Ok((socket, _)) = listener.accept() else {
                return;
            };
            let Ok(conn) = rustls::ServerConnection::new(config) else {
                return;
            };
            let mut tls = rustls::StreamOwned::new(conn, socket);
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                match tls.read(&mut byte) {
                    Ok(1) => head.push(byte[0]),
                    _ => return,
                }
            }
            let _ = tls
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
            tls.conn.send_close_notify();
            let _ = tls.flush();
        });

        addr
    }

    /// A client trusting only `roots`, with `localhost` pinned to `addr`.
    ///
    /// `tls_certs_only` makes reqwest use rustls's own `WebPkiServerVerifier`
    /// over exactly these roots. It does **not** go through
    /// rustls-platform-verifier (the `else` branch at
    /// `reqwest-0.13.4/src/async_impl/client.rs:784-788`, not the
    /// `Verifier::new` branch at `:748-758`). So the handshake tests
    /// prove reqwest's rustls stack verifies chains; they don't exercise the
    /// platform verifier. `a_client_builds_once_the_provider_is_installed`
    /// covers that one being constructed.
    ///
    /// `resolve` so the test never depends on whether `localhost` resolves to
    /// `::1` or `127.0.0.1` first. The URL's port is the one used.
    fn client_trusting(roots: &[&CertificateDer<'static>], addr: SocketAddr) -> reqwest::Client {
        reqwest::Client::builder()
            .tls_certs_only(
                roots
                    .iter()
                    .map(|der| reqwest::Certificate::from_der(der).unwrap()),
            )
            .resolve("localhost", addr)
            .no_proxy()
            .build()
            .unwrap()
    }

    /// The rustls error somewhere in `err`'s source chain, if there is one.
    ///
    /// A refused handshake is wrapped twice in `io::Error`:
    /// - tokio-rustls wraps the `rustls::Error`
    ///   (`tokio-rustls-0.26.4/src/common/mod.rs:115`)
    /// - hyper-rustls wraps that `io::Error` in `io::Error::other`
    ///   (`hyper-rustls-0.27.9/src/connector.rs:118-120`)
    ///
    /// reqwest then boxes the result under hyper-util's connect error. For a
    /// custom payload, `io::Error::source` returns the payload's *source*, not
    /// the payload, so walking with `source()` alone skips both layers. At
    /// every `io::Error` the walk steps into its payload with `get_ref`
    /// instead, which handles any depth of nesting.
    fn rustls_error_in(err: &reqwest::Error) -> Option<&rustls::Error> {
        let mut next: Option<&(dyn std::error::Error + 'static)> = Some(err);
        while let Some(current) = next {
            if let Some(tls) = current.downcast_ref::<rustls::Error>() {
                return Some(tls);
            }
            next = match current.downcast_ref::<std::io::Error>() {
                Some(io) => io
                    .get_ref()
                    .map(|payload| payload as &(dyn std::error::Error + 'static)),
                None => current.source(),
            };
        }
        None
    }

    #[test]
    fn installing_the_provider_twice_is_harmless() {
        install_crypto_provider();
        install_crypto_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }

    /// Exactly the constructor `main.rs` (`plc_client`) and `brolly-admin
    /// plc-retry` use. With `rustls-no-provider` and no provider installed,
    /// this panics inside reqwest.
    ///
    /// This one does read the OS: on Linux, building constructs
    /// rustls-platform-verifier, which loads the system root store and fails
    /// if it is empty. The test host needs a CA bundle. `ubuntu-latest` (CI)
    /// and `rust:1-bookworm` have `ca-certificates`; a slim container without
    /// it fails here with "No CA certificates were loaded from the system".
    #[test]
    fn a_client_builds_once_the_provider_is_installed() {
        install_crypto_provider();
        if let Err(e) = https_client() {
            panic!("{e}");
        }
    }

    /// Nothing may be `#[ignore]`d, so no call to a real host. A real handshake
    /// against a local server proves the same thing: the TLS stack reqwest
    /// was compiled with verifies a chain and completes a request.
    #[tokio::test]
    async fn https_completes_against_a_trusted_root() {
        install_crypto_provider();
        let pki = pki("brolly test CA");
        let addr = serve_once(pki.leaf, pki.leaf_key);
        let client = client_trusting(&[&pki.ca], addr);

        let response = client
            .get(format!("https://localhost:{}/", addr.port()))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "ok");
    }

    /// Without this, the test above would also pass against a client that
    /// verifies nothing.
    ///
    /// Asserts the refusal is certificate verification, not just "an error".
    /// `is_connect()` can't tell them apart: the handshake runs inside the
    /// connector, so a refused certificate and a refused TCP connection are
    /// both connect errors. The rustls error in the chain can.
    #[tokio::test]
    async fn https_refuses_a_certificate_from_an_untrusted_root() {
        install_crypto_provider();
        let served = pki("brolly test CA");
        let stranger = pki("stranger CA");
        let addr = serve_once(served.leaf, served.leaf_key);
        let client = client_trusting(&[&stranger.ca], addr);

        let err = match client
            .get(format!("https://localhost:{}/", addr.port()))
            .send()
            .await
        {
            Ok(response) => panic!("an unknown issuer was accepted: {}", response.status()),
            Err(err) => err,
        };

        let tls = rustls_error_in(&err);
        assert!(
            matches!(
                tls,
                Some(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer
                ))
            ),
            "expected the chain to be refused as UnknownIssuer, got rustls error {tls:?} in {err:?}",
        );
    }
}
