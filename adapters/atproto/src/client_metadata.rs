//! Which ATProto OAuth clients we talk to, and what they may ask for.
//!
//! Pure rules, no I/O: the server fetches a client's metadata document and
//! hands the bytes here. Each rule follows the ATProto OAuth specification
//! (<https://atproto.com/specs/oauth>), and the doc comments quote it, because
//! a rule looser than the spec is a hole and a stricter one is a real client
//! refused.
//!
//! This exists because PAR used to accept any `https://` `client_id`, never
//! fetch its metadata, and store whatever `redirect_uri` it was given, so an
//! authorization code went wherever a request asked.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Deserialize;
use url::{Host, Url};

/// A `client_id` that has passed [`parse_client_id`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientId {
    /// An `https` URL serving the client's metadata document.
    Discoverable(Url),
    /// `http://localhost`, "for development". It has no metadata document;
    /// [`loopback_metadata`] derives one from its query.
    Loopback(Url),
}

impl ClientId {
    pub fn url(&self) -> &Url {
        match self {
            ClientId::Discoverable(url) | ClientId::Loopback(url) => url,
        }
    }

    pub fn is_loopback(&self) -> bool {
        matches!(self, ClientId::Loopback(_))
    }
}

/// `application_type`. Absent means `web`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationType {
    Web,
    Native,
}

/// Client metadata that has passed [`validate`], or been derived by
/// [`loopback_metadata`].
///
/// The fields are private so nothing outside this module can build one. A
/// test double that holds `ClientMetadata` therefore holds only what
/// production would accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientMetadata {
    client_id: String,
    redirect_uris: Vec<String>,
    scope: String,
    token_endpoint_auth_method: String,
    dpop_bound_access_tokens: bool,
    application_type: ApplicationType,
    /// Loopback redirects match with the port ignored. Only ever true for
    /// metadata from [`loopback_metadata`].
    loopback: bool,
}

impl ClientMetadata {
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub fn redirect_uris(&self) -> &[String] {
        &self.redirect_uris
    }
    pub fn scope(&self) -> &str {
        &self.scope
    }
    pub fn token_endpoint_auth_method(&self) -> &str {
        &self.token_endpoint_auth_method
    }
    pub fn dpop_bound_access_tokens(&self) -> bool {
        self.dpop_bound_access_tokens
    }
    pub fn application_type(&self) -> ApplicationType {
        self.application_type
    }
}

/// Why a client, or what it asked for, was refused.
///
/// Every message is safe to show the caller: it names the rule, never anything
/// fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    InvalidClientId(&'static str),
    InvalidMetadata(&'static str),
    /// `private_key_jwt`. Accepting it without verifying the client assertion
    /// would be worse than refusing it (S6); stage 2.
    ConfidentialUnsupported,
    RedirectUriNotAllowed,
    ScopeNotAllowed(&'static str),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::InvalidClientId(rule) => f.write_str(rule),
            ClientError::InvalidMetadata(rule) => write!(f, "client metadata is invalid: {rule}"),
            ClientError::ConfidentialUnsupported => {
                f.write_str("confidential clients (private_key_jwt) are not supported yet")
            }
            ClientError::RedirectUriNotAllowed => {
                f.write_str("redirect_uri is not one the client's metadata declares")
            }
            ClientError::ScopeNotAllowed(rule) => f.write_str(rule),
        }
    }
}

impl std::error::Error for ClientError {}

const LOOPBACK_CLIENT: &str = "http://localhost";

/// Parse and check a `client_id`.
///
/// **Discoverable:** a well-formed `https` URL with no port, no userinfo and no
/// fragment, whose host is a domain name. Never an IP literal: hyper connects
/// to those without resolving them, so they would bypass the server's
/// public-address filter. It must also already be in canonical form, so the
/// string the client sent is the string its metadata has to repeat.
///
/// **Loopback:** exactly `http://localhost`, no port, path `/`, no fragment.
/// The query may carry `redirect_uri` (repeatable) and `scope`, and every
/// `redirect_uri` must be `http` on `127.0.0.1` or `[::1]`. Without that check
/// the loopback exception would send codes anywhere again.
pub fn parse_client_id(raw: &str) -> Result<ClientId, ClientError> {
    if raw.starts_with("http:") {
        return parse_loopback(raw);
    }
    let url = Url::parse(raw)
        .map_err(|_| ClientError::InvalidClientId("client_id must be an https URL"))?;
    if url.scheme() != "https" {
        return Err(ClientError::InvalidClientId(
            "client_id must be an https URL, or http://localhost for development",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ClientError::InvalidClientId(
            "client_id must not carry userinfo",
        ));
    }
    if url.port().is_some() {
        return Err(ClientError::InvalidClientId(
            "client_id must not have a port",
        ));
    }
    if url.fragment().is_some() {
        return Err(ClientError::InvalidClientId(
            "client_id must not have a fragment",
        ));
    }
    if !matches!(url.host(), Some(Host::Domain(_))) {
        return Err(ClientError::InvalidClientId(
            "client_id must name a host by domain, not by IP address",
        ));
    }
    if url.as_str() != raw {
        return Err(ClientError::InvalidClientId(
            "client_id must be in canonical form (lowercase host, no default port)",
        ));
    }
    Ok(ClientId::Discoverable(url))
}

fn parse_loopback(raw: &str) -> Result<ClientId, ClientError> {
    const NOT_LOOPBACK: ClientError = ClientError::InvalidClientId(
        "an http client_id must be exactly http://localhost, with no port or path",
    );
    // Literal prefix first: it rules out ports, userinfo, other hosts and
    // case variants before the URL parser can normalise any of them away.
    let rest = raw.strip_prefix(LOOPBACK_CLIENT).ok_or(NOT_LOOPBACK)?;
    if !(rest.is_empty() || rest.starts_with('/') || rest.starts_with('?')) {
        return Err(NOT_LOOPBACK);
    }
    let url = Url::parse(raw).map_err(|_| NOT_LOOPBACK)?;
    if url.host() != Some(Host::Domain("localhost")) || url.port().is_some() || url.path() != "/" {
        return Err(NOT_LOOPBACK);
    }
    if url.fragment().is_some() {
        return Err(ClientError::InvalidClientId(
            "client_id must not have a fragment",
        ));
    }
    let mut scopes = 0;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "redirect_uri" if !is_loopback_redirect(&value) => {
                return Err(ClientError::InvalidClientId(
                    "a localhost client's redirect_uri must be http://127.0.0.1 or http://[::1]",
                ));
            }
            "scope" => {
                scopes += 1;
                if scopes > 1 {
                    return Err(ClientError::InvalidClientId(
                        "a localhost client_id may name scope only once",
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(ClientId::Loopback(url))
}

fn is_loopback_redirect(uri: &str) -> bool {
    Url::parse(uri).is_ok_and(|url| url.scheme() == "http" && is_loopback_host(&url))
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(ip)) => ip == Ipv4Addr::LOCALHOST,
        Some(Host::Ipv6(ip)) => ip == Ipv6Addr::LOCALHOST,
        _ => false,
    }
}

/// The metadata a loopback client implies.
///
/// `redirect_uris` from the query, defaulting to `http://127.0.0.1/` and
/// `http://[::1]/`; `scope` from the query, defaulting to `atproto`; a public,
/// DPoP-bound, native client.
///
/// Given a discoverable id, which has real metadata to fetch, it returns
/// metadata that allows nothing: no redirect URIs and no scope.
pub fn loopback_metadata(id: &ClientId) -> ClientMetadata {
    let ClientId::Loopback(url) = id else {
        return ClientMetadata {
            client_id: id.url().as_str().to_owned(),
            redirect_uris: Vec::new(),
            scope: String::new(),
            token_endpoint_auth_method: "none".to_owned(),
            dpop_bound_access_tokens: true,
            application_type: ApplicationType::Native,
            loopback: false,
        };
    };
    let mut redirect_uris = Vec::new();
    let mut scope = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "redirect_uri" => redirect_uris.push(value.into_owned()),
            "scope" => scope = Some(value.into_owned()),
            _ => {}
        }
    }
    if redirect_uris.is_empty() {
        redirect_uris = vec!["http://127.0.0.1/".to_owned(), "http://[::1]/".to_owned()];
    }
    ClientMetadata {
        client_id: url.as_str().to_owned(),
        redirect_uris,
        scope: scope.unwrap_or_else(|| "atproto".to_owned()),
        token_endpoint_auth_method: "none".to_owned(),
        dpop_bound_access_tokens: true,
        application_type: ApplicationType::Native,
        loopback: true,
    }
}

/// The fields we read. Everything else, `client_name` and `logo_uri`
/// included, is ignored: without a vetted list they are self-asserted and not
/// shown (S5).
#[derive(Deserialize)]
struct Document {
    client_id: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
    scope: Option<String>,
    #[serde(default)]
    grant_types: Vec<String>,
    #[serde(default)]
    response_types: Vec<String>,
    dpop_bound_access_tokens: Option<bool>,
    token_endpoint_auth_method: Option<String>,
    application_type: Option<String>,
}

/// Check a fetched metadata document against the `client_id` it was fetched
/// from.
pub fn validate(
    id: &ClientId,
    content_type: &str,
    body: &[u8],
) -> Result<ClientMetadata, ClientError> {
    let ClientId::Discoverable(url) = id else {
        return Err(ClientError::InvalidClientId(
            "a localhost client has no metadata document",
        ));
    };

    let media_type = content_type.split(';').next().unwrap_or_default().trim();
    if !media_type.eq_ignore_ascii_case("application/json") {
        return Err(ClientError::InvalidMetadata(
            "client metadata must be served as application/json",
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|_| ClientError::InvalidMetadata("client metadata is not a JSON object"))?;
    if !value.is_object() {
        return Err(ClientError::InvalidMetadata(
            "client metadata is not a JSON object",
        ));
    }
    let doc: Document = serde_json::from_value(value)
        .map_err(|_| ClientError::InvalidMetadata("a client metadata field has the wrong type"))?;

    // "the client_id ... must exactly match the URL used to fetch the document"
    if doc.client_id.as_deref() != Some(url.as_str()) {
        return Err(ClientError::InvalidMetadata(
            "client_id does not match the URL the metadata was fetched from",
        ));
    }
    // "dpop_bound_access_tokens (boolean, required): DPoP is mandatory ... must be true"
    if doc.dpop_bound_access_tokens != Some(true) {
        return Err(ClientError::InvalidMetadata(
            "dpop_bound_access_tokens must be true",
        ));
    }
    // "grant_types ... authorization_code must always be included"
    if !doc.grant_types.iter().any(|g| g == "authorization_code") {
        return Err(ClientError::InvalidMetadata(
            "grant_types must include authorization_code",
        ));
    }
    // "response_types ... code must be included"
    if !doc.response_types.iter().any(|r| r == "code") {
        return Err(ClientError::InvalidMetadata(
            "response_types must include code",
        ));
    }
    // "scope (string, sub-strings space-separated, required): ... must include atproto"
    let scope = doc.scope.unwrap_or_default();
    if !scope.split(' ').any(|s| s == "atproto") {
        return Err(ClientError::InvalidMetadata("scope must include atproto"));
    }
    // "token_endpoint_auth_method ... none (public client) or private_key_jwt
    // (confidential client)"
    match doc.token_endpoint_auth_method.as_deref() {
        None | Some("none") => {}
        Some("private_key_jwt") => return Err(ClientError::ConfidentialUnsupported),
        Some(_) => {
            return Err(ClientError::InvalidMetadata(
                "token_endpoint_auth_method must be none",
            ));
        }
    }
    // "application_type (string, optional): must be one of web or native,
    // with web as the default if not specified"
    let application_type = match doc.application_type.as_deref() {
        None | Some("web") => ApplicationType::Web,
        Some("native") => ApplicationType::Native,
        Some(_) => {
            return Err(ClientError::InvalidMetadata(
                "application_type must be web or native",
            ));
        }
    };
    // "redirect_uris (array of strings, required): at least one redirect URI is required"
    if doc.redirect_uris.is_empty() {
        return Err(ClientError::InvalidMetadata(
            "redirect_uris must not be empty",
        ));
    }
    for uri in &doc.redirect_uris {
        match application_type {
            ApplicationType::Web if !is_https(uri) => {
                return Err(ClientError::InvalidMetadata(
                    "a web client's redirect_uris must be https URLs",
                ));
            }
            ApplicationType::Native if !is_native_redirect(url, uri) => {
                return Err(ClientError::InvalidMetadata(
                    "a native client's redirect_uris must use its reverse-domain scheme \
                     or its own https origin",
                ));
            }
            _ => {}
        }
    }

    Ok(ClientMetadata {
        client_id: url.as_str().to_owned(),
        redirect_uris: doc.redirect_uris,
        scope,
        token_endpoint_auth_method: "none".to_owned(),
        dpop_bound_access_tokens: true,
        application_type,
        loopback: false,
    })
}

fn is_https(uri: &str) -> bool {
    Url::parse(uri).is_ok_and(|url| url.scheme() == "https")
}

/// A native client's redirect: "Any custom scheme must match the client_id
/// hostname in reverse-domain order. The URI scheme must be followed by a
/// single colon (:) then a single forward slash (/) and then a URI path
/// component" — or an `https` URL on the client's own origin.
///
/// Loopback `http` redirects, which the spec also allows for native clients,
/// are refused until stage 2.
fn is_native_redirect(client: &Url, uri: &str) -> bool {
    let Ok(redirect) = Url::parse(uri) else {
        return false;
    };
    match redirect.scheme() {
        "https" => redirect.origin() == client.origin(),
        "http" => false,
        _ => {
            let Some(host) = client.host_str() else {
                return false;
            };
            let scheme = host.split('.').rev().collect::<Vec<_>>().join(".");
            uri.strip_prefix(scheme.as_str())
                .and_then(|rest| rest.strip_prefix(':'))
                .is_some_and(|path| path.starts_with('/') && !path.starts_with("//"))
        }
    }
}

/// May this client make this request?
///
/// **Redirect URI:** "must exactly match one of the redirect_uris in the
/// client metadata". For a loopback client, `127.0.0.1` and `[::1]` redirects
/// match with the port ignored ("path component matched but port numbers
/// ignored"); everything else about them still has to match.
///
/// **Scope:** "Must include atproto", and the requested scopes "must be a
/// subset" of the client's declared scope.
pub fn check_request(
    metadata: &ClientMetadata,
    redirect_uri: &str,
    scope: &str,
) -> Result<(), ClientError> {
    let declared = metadata.redirect_uris.iter().any(|allowed| {
        allowed == redirect_uri
            || (metadata.loopback && same_loopback_redirect(allowed, redirect_uri))
    });
    if !declared {
        return Err(ClientError::RedirectUriNotAllowed);
    }

    let requested: Vec<&str> = scope.split(' ').filter(|s| !s.is_empty()).collect();
    if !requested.contains(&"atproto") {
        return Err(ClientError::ScopeNotAllowed("scope must include atproto"));
    }
    let allowed: Vec<&str> = metadata.scope.split(' ').collect();
    if requested.iter().any(|s| !allowed.contains(s)) {
        return Err(ClientError::ScopeNotAllowed(
            "scope asks for more than the client's metadata declares",
        ));
    }
    Ok(())
}

fn same_loopback_redirect(allowed: &str, requested: &str) -> bool {
    let (Ok(mut allowed), Ok(mut requested)) = (Url::parse(allowed), Url::parse(requested)) else {
        return false;
    };
    requested.scheme() == "http"
        && is_loopback_host(&requested)
        && allowed.set_port(None).is_ok()
        && requested.set_port(None).is_ok()
        && allowed == requested
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const APP: &str = "https://app.example/client-metadata.json";
    const NATIVE: &str = "https://app.example.com/client-metadata.json";

    // --- helpers ------------------------------------------------------------

    fn id(raw: &str) -> ClientId {
        parse_client_id(raw).unwrap_or_else(|e| panic!("{raw} should parse: {e}"))
    }

    fn refused_id(raw: &str) {
        assert!(
            matches!(parse_client_id(raw), Err(ClientError::InvalidClientId(_))),
            "{raw} should be refused as a client_id, got {:?}",
            parse_client_id(raw)
        );
    }

    fn web_document() -> Value {
        json!({
            "client_id": APP,
            "client_name": "Example App",
            "redirect_uris": ["https://app.example/cb"],
            "scope": "atproto transition:generic",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "application_type": "web",
            "dpop_bound_access_tokens": true,
        })
    }

    fn native_document(redirect: &str) -> Value {
        json!({
            "client_id": NATIVE,
            "redirect_uris": [redirect],
            "scope": "atproto",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "application_type": "native",
            "dpop_bound_access_tokens": true,
        })
    }

    fn validating(document: &Value) -> Result<ClientMetadata, ClientError> {
        validate(
            &id(APP),
            "application/json",
            document.to_string().as_bytes(),
        )
    }

    fn validating_native(redirect: &str) -> Result<ClientMetadata, ClientError> {
        validate(
            &id(NATIVE),
            "application/json",
            native_document(redirect).to_string().as_bytes(),
        )
    }

    fn with(mut document: Value, field: &str, value: Value) -> Value {
        document[field] = value;
        document
    }

    fn without(mut document: Value, field: &str) -> Value {
        document.as_object_mut().unwrap().remove(field);
        document
    }

    /// Refused as invalid metadata, for the rule named by `rule`.
    fn refused_for(result: Result<ClientMetadata, ClientError>, rule: &str) {
        match result {
            Err(ClientError::InvalidMetadata(message)) => assert!(
                message.contains(rule),
                "refused for {message:?}, expected the {rule:?} rule"
            ),
            other => panic!("expected InvalidMetadata for {rule:?}, got {other:?}"),
        }
    }

    // --- parse_client_id: discoverable ------------------------------------------

    #[test]
    fn an_https_client_id_is_discoverable() {
        assert!(matches!(id(APP), ClientId::Discoverable(_)));
        assert_eq!(id(APP).url().as_str(), APP);
        assert!(!id(APP).is_loopback());
    }

    #[test]
    fn a_client_id_with_a_port_is_refused() {
        refused_id("https://app.example:8443/client-metadata.json");
    }

    #[test]
    fn a_client_id_with_userinfo_is_refused() {
        refused_id("https://user@app.example/client-metadata.json");
        refused_id("https://user:secret@app.example/client-metadata.json");
    }

    #[test]
    fn a_client_id_with_a_fragment_is_refused() {
        refused_id("https://app.example/client-metadata.json#x");
        refused_id("https://app.example/client-metadata.json#");
    }

    #[test]
    fn a_client_id_with_an_ip_host_is_refused() {
        // hyper connects to IP literals without resolving them, so they would
        // never pass through the PublicOnly resolver.
        refused_id("https://203.0.113.9/client-metadata.json");
        refused_id("https://127.0.0.1/client-metadata.json");
        refused_id("https://[2001:db8::1]/client-metadata.json");
        refused_id("https://[::1]/client-metadata.json");
    }

    #[test]
    fn a_client_id_not_in_canonical_form_is_refused() {
        // "client_id equals the fetch URL, as an exact string" needs there to
        // be one string. The url crate would silently lowercase the host and
        // drop a default port.
        refused_id("https://APP.example/client-metadata.json");
        refused_id("https://app.example:443/client-metadata.json");
    }

    #[test]
    fn a_client_id_that_is_not_an_https_url_is_refused() {
        refused_id("http://app.example/client-metadata.json");
        refused_id("urn:uuid:1234");
        refused_id("my-app");
        refused_id("");
    }

    // --- parse_client_id: loopback ---------------------------------------------

    #[test]
    fn http_localhost_is_a_loopback_client() {
        for raw in [
            "http://localhost",
            "http://localhost/",
            "http://localhost?scope=atproto",
            "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Fcb",
            "http://localhost/?redirect_uri=http%3A%2F%2F%5B%3A%3A1%5D%3A9000%2Fcb&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcb",
        ] {
            assert!(id(raw).is_loopback(), "{raw}");
        }
    }

    #[test]
    fn a_loopback_client_id_with_a_port_path_or_fragment_is_refused() {
        refused_id("http://localhost:3000");
        refused_id("http://localhost:80/");
        refused_id("http://localhost/client-metadata.json");
        refused_id("http://localhost/#x");
        refused_id("http://localhost.evil.example/");
        refused_id("http://localhost@evil.example/");
        refused_id("http://127.0.0.1/");
    }

    #[test]
    fn a_loopback_client_id_naming_an_external_redirect_is_refused() {
        // Without this the loopback exception would reopen hole 3.
        refused_id("http://localhost?redirect_uri=https%3A%2F%2Fevil.example%2Fcb");
        refused_id("http://localhost?redirect_uri=http%3A%2F%2Fevil.example%2Fcb");
        // localhost the *name* is not a loopback redirect; only the addresses are.
        refused_id("http://localhost?redirect_uri=http%3A%2F%2Flocalhost%2Fcb");
        refused_id("http://localhost?redirect_uri=https%3A%2F%2F127.0.0.1%2Fcb");
    }

    #[test]
    fn a_loopback_client_id_with_two_scopes_is_refused() {
        refused_id("http://localhost?scope=atproto&scope=transition%3Ageneric");
    }

    // --- loopback_metadata --------------------------------------------------------

    #[test]
    fn loopback_metadata_has_the_spec_defaults() {
        let meta = loopback_metadata(&id("http://localhost"));
        assert_eq!(
            meta.redirect_uris(),
            ["http://127.0.0.1/".to_string(), "http://[::1]/".to_string()]
        );
        assert_eq!(meta.scope(), "atproto");
        assert_eq!(meta.token_endpoint_auth_method(), "none");
        assert!(meta.dpop_bound_access_tokens());
        assert_eq!(meta.application_type(), ApplicationType::Native);
    }

    #[test]
    fn loopback_metadata_takes_redirects_and_scope_from_the_query() {
        let meta = loopback_metadata(&id(
            "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&scope=atproto%20transition%3Ageneric",
        ));
        assert_eq!(
            meta.redirect_uris(),
            ["http://127.0.0.1/callback".to_string()]
        );
        assert_eq!(meta.scope(), "atproto transition:generic");
    }

    #[test]
    fn loopback_metadata_for_a_discoverable_id_allows_nothing() {
        let meta = loopback_metadata(&id(APP));
        assert!(check_request(&meta, "http://127.0.0.1/", "atproto").is_err());
    }

    // --- validate -------------------------------------------------------------------

    #[test]
    fn a_complete_web_document_validates() {
        let meta = validating(&web_document()).unwrap();
        assert_eq!(meta.client_id(), APP);
        assert_eq!(meta.redirect_uris(), ["https://app.example/cb".to_string()]);
        assert_eq!(meta.scope(), "atproto transition:generic");
        assert_eq!(meta.application_type(), ApplicationType::Web);
    }

    #[test]
    fn the_content_type_must_be_json() {
        let body = web_document().to_string();
        assert!(validate(&id(APP), "application/json; charset=utf-8", body.as_bytes()).is_ok());
        assert!(validate(&id(APP), "Application/JSON", body.as_bytes()).is_ok());
        refused_for(
            validate(&id(APP), "text/html", body.as_bytes()),
            "application/json",
        );
        refused_for(validate(&id(APP), "", body.as_bytes()), "application/json");
    }

    #[test]
    fn the_body_must_be_a_json_object() {
        refused_for(validate(&id(APP), "application/json", b"[]"), "JSON object");
        refused_for(
            validate(&id(APP), "application/json", b"<html>"),
            "JSON object",
        );
        refused_for(
            validating(&with(
                web_document(),
                "redirect_uris",
                json!("https://app.example/cb"),
            )),
            "wrong type",
        );
    }

    #[test]
    fn the_client_id_must_equal_the_fetch_url() {
        refused_for(
            validating(&with(
                web_document(),
                "client_id",
                json!("https://other.example/client-metadata.json"),
            )),
            "client_id",
        );
        refused_for(
            validating(&without(web_document(), "client_id")),
            "client_id",
        );
        refused_for(
            validating(&with(
                web_document(),
                "client_id",
                json!("https://app.example/client-metadata.json/"),
            )),
            "client_id",
        );
    }

    #[test]
    fn a_loopback_id_has_no_document_to_validate() {
        assert!(matches!(
            validate(
                &id("http://localhost"),
                "application/json",
                web_document().to_string().as_bytes()
            ),
            Err(ClientError::InvalidClientId(_))
        ));
    }

    #[test]
    fn dpop_bound_access_tokens_must_be_true() {
        refused_for(
            validating(&without(web_document(), "dpop_bound_access_tokens")),
            "dpop_bound_access_tokens",
        );
        refused_for(
            validating(&with(
                web_document(),
                "dpop_bound_access_tokens",
                json!(false),
            )),
            "dpop_bound_access_tokens",
        );
    }

    #[test]
    fn grant_types_must_include_authorization_code() {
        refused_for(
            validating(&with(
                web_document(),
                "grant_types",
                json!(["refresh_token"]),
            )),
            "grant_types",
        );
        refused_for(
            validating(&without(web_document(), "grant_types")),
            "grant_types",
        );
    }

    #[test]
    fn response_types_must_include_code() {
        refused_for(
            validating(&with(web_document(), "response_types", json!(["token"]))),
            "response_types",
        );
        refused_for(
            validating(&without(web_document(), "response_types")),
            "response_types",
        );
    }

    #[test]
    fn the_declared_scope_must_include_atproto() {
        refused_for(
            validating(&with(web_document(), "scope", json!("transition:generic"))),
            "scope",
        );
        refused_for(validating(&without(web_document(), "scope")), "scope");
        // Split on spaces, not substring-matched.
        refused_for(
            validating(&with(web_document(), "scope", json!("atprotox"))),
            "scope",
        );
    }

    #[test]
    fn a_public_client_may_omit_or_name_the_auth_method() {
        assert!(validating(&without(web_document(), "token_endpoint_auth_method")).is_ok());
    }

    #[test]
    fn private_key_jwt_is_refused_as_confidential() {
        assert_eq!(
            validating(&with(
                web_document(),
                "token_endpoint_auth_method",
                json!("private_key_jwt")
            )),
            Err(ClientError::ConfidentialUnsupported)
        );
        refused_for(
            validating(&with(
                web_document(),
                "token_endpoint_auth_method",
                json!("client_secret_basic"),
            )),
            "token_endpoint_auth_method",
        );
    }

    #[test]
    fn application_type_is_web_native_or_absent() {
        let absent = validating(&without(web_document(), "application_type")).unwrap();
        assert_eq!(absent.application_type(), ApplicationType::Web);
        refused_for(
            validating(&with(web_document(), "application_type", json!("desktop"))),
            "application_type",
        );
    }

    #[test]
    fn redirect_uris_must_not_be_empty() {
        refused_for(
            validating(&with(web_document(), "redirect_uris", json!([]))),
            "redirect_uris must not be empty",
        );
        refused_for(
            validating(&without(web_document(), "redirect_uris")),
            "redirect_uris must not be empty",
        );
    }

    #[test]
    fn a_web_client_must_redirect_to_https() {
        refused_for(
            validating(&with(
                web_document(),
                "redirect_uris",
                json!(["http://app.example/cb"]),
            )),
            "web client",
        );
        // Loopback redirects belong to loopback clients only.
        refused_for(
            validating(&with(
                web_document(),
                "redirect_uris",
                json!(["http://127.0.0.1/cb"]),
            )),
            "web client",
        );
        // Every entry is checked, not just the first.
        refused_for(
            validating(&with(
                web_document(),
                "redirect_uris",
                json!(["https://app.example/cb", "http://app.example/cb"]),
            )),
            "web client",
        );
    }

    #[test]
    fn a_native_client_may_use_its_reverse_domain_scheme() {
        assert!(validating_native("com.example.app:/callback").is_ok());
    }

    #[test]
    fn a_native_client_with_a_scheme_that_does_not_match_is_refused() {
        refused_for(validating_native("com.evil.app:/callback"), "native client");
        refused_for(
            validating_native("app.example.com:/callback"),
            "native client",
        );
        // "a single colon then a single forward slash"
        refused_for(
            validating_native("com.example.app://callback"),
            "native client",
        );
        refused_for(
            validating_native("com.example.app:callback"),
            "native client",
        );
    }

    #[test]
    fn a_native_client_may_use_https_on_its_own_origin_only() {
        assert!(validating_native("https://app.example.com/callback").is_ok());
        refused_for(
            validating_native("https://evil.example/callback"),
            "native client",
        );
    }

    #[test]
    fn a_native_client_may_not_use_loopback_redirects_yet() {
        // A deliberate divergence from the ATProto spec, revisited in stage 2.
        refused_for(
            validating_native("http://127.0.0.1/callback"),
            "native client",
        );
        refused_for(validating_native("http://[::1]/callback"), "native client");
    }

    // --- check_request ------------------------------------------------------------

    #[test]
    fn a_declared_redirect_uri_is_accepted_exactly() {
        let web = validating(&web_document()).unwrap();
        assert_eq!(
            check_request(&web, "https://app.example/cb", "atproto"),
            Ok(())
        );
        assert_eq!(
            check_request(&web, "https://evil.example/cb", "atproto"),
            Err(ClientError::RedirectUriNotAllowed)
        );
        assert_eq!(
            check_request(&web, "https://app.example/cb/", "atproto"),
            Err(ClientError::RedirectUriNotAllowed)
        );
    }

    #[test]
    fn a_web_client_gets_no_port_leniency() {
        let web = validating(&web_document()).unwrap();
        assert_eq!(
            check_request(&web, "https://app.example:8443/cb", "atproto"),
            Err(ClientError::RedirectUriNotAllowed)
        );
    }

    #[test]
    fn a_loopback_redirect_on_a_different_port_is_accepted() {
        let meta = loopback_metadata(&id(
            "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback",
        ));
        assert_eq!(
            check_request(&meta, "http://127.0.0.1:61234/callback", "atproto"),
            Ok(())
        );
        let defaults = loopback_metadata(&id("http://localhost"));
        assert_eq!(
            check_request(&defaults, "http://[::1]:4000/", "atproto"),
            Ok(())
        );
    }

    #[test]
    fn a_loopback_redirect_on_a_different_path_is_refused() {
        let meta = loopback_metadata(&id(
            "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback",
        ));
        assert_eq!(
            check_request(&meta, "http://127.0.0.1:61234/elsewhere", "atproto"),
            Err(ClientError::RedirectUriNotAllowed)
        );
        assert_eq!(
            check_request(&meta, "http://[::1]:61234/callback", "atproto"),
            Err(ClientError::RedirectUriNotAllowed),
            "the host is matched too"
        );
    }

    #[test]
    fn a_requested_scope_without_atproto_is_refused() {
        let web = validating(&web_document()).unwrap();
        assert!(matches!(
            check_request(&web, "https://app.example/cb", "transition:generic"),
            Err(ClientError::ScopeNotAllowed(_))
        ));
        assert!(matches!(
            check_request(&web, "https://app.example/cb", ""),
            Err(ClientError::ScopeNotAllowed(_))
        ));
    }

    #[test]
    fn a_scope_escalation_is_refused() {
        let narrow = validating(&with(web_document(), "scope", json!("atproto"))).unwrap();
        assert!(matches!(
            check_request(
                &narrow,
                "https://app.example/cb",
                "atproto transition:generic"
            ),
            Err(ClientError::ScopeNotAllowed(_))
        ));
    }

    #[test]
    fn a_subset_of_the_declared_scope_is_accepted() {
        let web = validating(&web_document()).unwrap();
        assert_eq!(
            check_request(&web, "https://app.example/cb", "atproto"),
            Ok(())
        );
        assert_eq!(
            check_request(&web, "https://app.example/cb", "transition:generic atproto"),
            Ok(())
        );
    }
}
