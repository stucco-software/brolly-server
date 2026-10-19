//! Solid-OIDC Client ID Documents (spec 6, H3).
//!
//! Most real Solid apps are their own client registration: an RDF document at
//! their `client_id` URL, fetched and validated instead of looked up in a
//! table. The fetching — the hardened transport the ATProto side already
//! proved — lives in `brolly_server::client_metadata`, parameterized by the
//! [`ClientIdDocument`] this module defines; everything here is what varies
//! with the protocol: the RDF [`Accept`][ACCEPT] the fetch asks for, the
//! content-type check, the parse, and the rules a validated document applies
//! to a request's `redirect_uri`.
//!
//! The Solid-OIDC spec (§5.1) defines the document through its normative
//! JSON-LD context rather than prose: `client_id` maps to `@id`, so the
//! document's subject *is* the client's own IRI, and `redirect_uris` maps to
//! [`vocab::SOLID_OIDC_REDIRECT_URIS`] with an `@id`/`@set` container, so each
//! listed URI is a direct object on that subject. A document with no such
//! triples is not declaring itself a client at all — which is how "must
//! declare itself an OAuth/Solid-OIDC client" is checked here; the spec has no
//! rdf:type for it to be checked against.

use std::collections::BTreeSet;

use brolly_domain::syntax::{self, ReadFormat};
use brolly_domain::vocab;
use oxigraph::io::{JsonLdProfile, JsonLdProfileSet, LoadedDocument, RdfFormat, RdfParser};
use oxigraph::model::{NamedNode, NamedOrBlankNode, Quad, Term};
use url::{Host, Url};

/// What a Client ID Document fetch asks for, and what it will accept: every
/// RDF serialization we can parse, most-preferred first. The list is
/// load-bearing in both directions — it must not contain `*/*` or anything
/// that sounds like a browser, or a server such as this one serves the HTML
/// page it keeps for browsers, and it must include `application/ld+json`,
/// because that is the only serialization the Solid-OIDC spec *requires* a
/// Client ID Document to be available as. `application/json` rides along:
/// Penny — and a fair share of the ecosystem beside — serves its document
/// under that label, and it parses as JSON-LD or not at all.
pub const ACCEPT: &str = "text/turtle, application/n-triples, application/n-quads, \
                          application/trig, application/ld+json, application/json";

/// Where the normative JSON-LD context lives. The one remote document the
/// parse is allowed to know the contents of — see [`OIDC_CONTEXT`].
const CONTEXT_URL: &str = "https://www.w3.org/ns/solid/oidc-context.jsonld";

/// The Solid-OIDC spec's normative JSON-LD context, verbatim from its
/// Appendix A.
///
/// A JSON-LD Client ID Document references this by URL, and without it
/// `redirect_uris` expands to nothing. The parse must not fetch it — that
/// would be a second network fetch inside the validation of an untrusted
/// document — so it is embedded here, byte-for-byte as the spec defines it,
/// and the parse answers the context URL with these bytes and nothing else.
const OIDC_CONTEXT: &str = r#"{
  "@context": {
    "@version": 1.1,
    "@protected": true,
    "oidc": "http://www.w3.org/ns/solid/oidc#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "client_id": {
      "@id": "@id",
      "@type": "@id"
    },
    "client_uri": {
      "@id": "oidc:client_uri",
      "@type": "@id"
    },
    "logo_uri": {
      "@id": "oidc:logo_uri",
      "@type": "@id"
    },
    "policy_uri": {
      "@id": "oidc:policy_uri",
      "@type": "@id"
    },
    "tos_uri": {
      "@id": "oidc:tos_uri",
      "@type": "@id"
    },
    "redirect_uris": {
      "@id": "oidc:redirect_uris",
      "@type": "@id",
      "@container": [
        "@id",
        "@set"
      ]
    },
    "require_auth_time": {
      "@id": "oidc:require_auth_time",
      "@type": "xsd:boolean"
    },
    "default_max_age": {
      "@id": "oidc:default_max_age",
      "@type": "xsd:integer"
    },
    "application_type": {
      "@id": "oidc:application_type"
    },
    "client_name": {
      "@id": "oidc:client_name"
    },
    "contacts": {
      "@id": "oidc:contacts"
    },
    "grant_types": {
      "@id": "oidc:grant_types"
    },
    "response_types": {
      "@id": "oidc:response_types"
    },
    "scope": {
      "@id": "oidc:scope"
    },
    "token_endpoint_auth_method": {
      "@id": "oidc:token_endpoint_auth_method"
    }
  }
}"#;

/// A Client ID Document that has passed [`parse`].
///
/// The fields are private so nothing outside this module can build one; a
/// fetch that yields a `ClientIdDocument` has validated it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdDocument {
    client_id: String,
    client_name: Option<String>,
    redirect_uris: Vec<String>,
}

impl ClientIdDocument {
    /// The IRI the document was fetched from — which is its client_id: the
    /// normative context maps `client_id` to `@id`.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The client's name, for the consent screen. `None` if the document
    /// carries none; the caller then falls back the way it does for a
    /// registered client without one.
    pub fn client_name(&self) -> Option<&str> {
        self.client_name.as_deref()
    }
}

/// Why fetched bytes are not a usable Client ID Document.
///
/// Every message names the rule, never anything fetched: the operator's log
/// gets the detail, and the member asking to authorize gets one answer for
/// every cause (spec 6, H3), so these strings never reach a caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidDocument {
    /// Served as something RDF is not served as. Our own `/profile` serves
    /// HTML to anything that sounds like a browser, so a fetch that does not
    /// ask for RDF gets a page — this is the refusal that catches it.
    NotRdf(String),
    /// The body did not parse as its content type claimed.
    Unparseable(String),
    /// Parsed, but not a Client ID Document: no redirect URIs on the
    /// client's own IRI.
    NotAClientDocument,
}

impl std::fmt::Display for InvalidDocument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidDocument::NotRdf(content_type) => {
                write!(
                    f,
                    "a client id document must be served as RDF, not {content_type}"
                )
            }
            InvalidDocument::Unparseable(e) => {
                write!(f, "the client id document did not parse: {e}")
            }
            InvalidDocument::NotAClientDocument => f.write_str(
                "the document lists no redirect URIs on the client's own IRI, \
                 so it is not a client id document",
            ),
        }
    }
}

impl std::error::Error for InvalidDocument {}

/// The format a fetched document's content type names.
///
/// `application/json` is a JSON-LD attempt, not a `NotRdf`. The Solid-OIDC
/// spec (§5.1) says the document "MUST be serialized as an
/// `application/ld+json` document", but the label is where the ecosystem's
/// compliance ends: Penny — a finish-line client — serves the spec's own
/// JSON form under the plain `application/json`. The bytes are what matter,
/// and they take the same JSON-LD parse an honest `application/ld+json`
/// takes — the normative context or no parse, the client's own triples or no
/// client — so a plain JSON body fails exactly as it would have under the
/// honest label. Nothing else moves: `text/html` and `text/plain` are still
/// `NotRdf`, because they are the labels an HTML page wears.
fn document_format(content_type: &str) -> Result<ReadFormat, InvalidDocument> {
    if syntax::media_type_of(content_type) == "application/json" {
        return Ok(ReadFormat::JsonLd);
    }
    syntax::read_format(content_type).map_err(|_| InvalidDocument::NotRdf(content_type.to_string()))
}

/// Parse and validate the document at `client_id`: the content-type check and
/// the RDF parse the fetch is parameterized with (spec 6, H3).
///
/// The base IRI is the client's own IRI, so a document that describes itself
/// with `<>` describes the client. Any RDF serialization we parse is
/// accepted; JSON-LD additionally resolves the Solid-OIDC spec's normative
/// context from [`OIDC_CONTEXT`] — a document referencing any other remote
/// context is refused rather than fetched.
pub fn parse(
    client_id: &Url,
    content_type: &str,
    body: &[u8],
) -> Result<ClientIdDocument, InvalidDocument> {
    let format = document_format(content_type)?;
    // `application/rdf+xml` is a `NotRdf` too, by design: we serialize it but
    // never parse it (ADR 0007), and a fetched document is exactly the
    // untrusted input that rule exists for.
    let quads = match format {
        // The spec's default serialization. Its normative context is
        // embedded rather than fetched: a parse must not do I/O, and a
        // document's choice of context must not turn into a URL we fetch.
        ReadFormat::JsonLd => json_ld(client_id, body)?,
        other => syntax::parse(body, other, client_id.as_str())
            .map_err(|e| InvalidDocument::Unparseable(e.to_string()))?,
    };

    // The document declares itself a client by carrying the client's own
    // triples: the normative context maps `client_id` to `@id`, so the
    // subject is the IRI the document was fetched from. Triples about any
    // other node are not the client's.
    let subject = NamedOrBlankNode::NamedNode(NamedNode::new_unchecked(client_id.as_str()));
    let mut redirect_uris: BTreeSet<String> = BTreeSet::new();
    let mut client_name = None;
    let mut collections: Vec<NamedOrBlankNode> = Vec::new();
    for quad in &quads {
        if quad.subject != subject {
            continue;
        }
        if quad.predicate.as_str() == vocab::SOLID_OIDC_REDIRECT_URIS {
            match &quad.object {
                // The normative JSON-LD context's `@set` container: each
                // listed URI is a direct object.
                Term::NamedNode(uri) => {
                    redirect_uris.insert(uri.as_str().to_owned());
                }
                // A hand-written Turtle document may instead hang an RDF
                // collection off the predicate; those are walked below.
                Term::BlankNode(head) => {
                    collections.push(NamedOrBlankNode::BlankNode(head.clone()));
                }
                _ => {}
            }
        } else if client_name.is_none()
            && quad.predicate.as_str() == vocab::SOLID_OIDC_CLIENT_NAME
            && let Term::Literal(name) = &quad.object
        {
            client_name = Some(name.value().to_string());
        }
    }
    for head in collections {
        follow_collection(&quads, &head, &mut |uri| {
            redirect_uris.insert(uri);
        });
    }
    if redirect_uris.is_empty() {
        return Err(InvalidDocument::NotAClientDocument);
    }
    Ok(ClientIdDocument {
        client_id: client_id.as_str().to_owned(),
        client_name,
        redirect_uris: redirect_uris.into_iter().collect(),
    })
}

/// A JSON-LD parse with the normative context answered locally.
fn json_ld(base: &Url, body: &[u8]) -> Result<Vec<Quad>, InvalidDocument> {
    RdfParser::from_format(RdfFormat::JsonLd {
        profile: JsonLdProfileSet::empty(),
    })
    .with_base_iri(base.as_str())
    .map_err(|e| InvalidDocument::Unparseable(e.to_string()))?
    .for_slice(body)
    .with_document_loader(|url| {
        // Only the spec's own context, and only these bytes. Anything else a
        // document asks for is a context we do not know, so the document is
        // not one we can read — never a URL to fetch.
        if url != CONTEXT_URL {
            return Err(format!("remote context {url} is not the Solid-OIDC context").into());
        }
        Ok(LoadedDocument {
            url: CONTEXT_URL.into(),
            content: OIDC_CONTEXT.as_bytes().to_vec(),
            format: RdfFormat::JsonLd {
                profile: JsonLdProfile::Context.into(),
            },
        })
    })
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| InvalidDocument::Unparseable(e.to_string()))
}

/// Walk one RDF collection hung off `oidc:redirect_uris`, adding every `rdf:first`
/// element that is an IRI.
///
/// Bounded by the quad count: a well-formed chain visits each node at most
/// once, so a longer walk means a cycle, and it stops instead of looping.
fn follow_collection(quads: &[Quad], head: &NamedOrBlankNode, add: &mut impl FnMut(String)) {
    let mut node = head.clone();
    for _ in 0..quads.len() {
        let mut next = None;
        for quad in quads {
            if quad.subject != node {
                continue;
            }
            match quad.predicate.as_str() {
                vocab::RDF_FIRST => {
                    if let Term::NamedNode(uri) = &quad.object {
                        add(uri.as_str().to_owned());
                    }
                }
                vocab::RDF_REST => {
                    next = Some(match &quad.object {
                        Term::BlankNode(rest) => NamedOrBlankNode::BlankNode(rest.clone()),
                        // `rdf:nil` ends the chain; anything else is not a
                        // collection this walk can follow.
                        _ => return,
                    });
                }
                _ => {}
            }
        }
        match next {
            Some(next) => node = next,
            None => return,
        }
    }
}

/// May this client be sent to `redirect_uri`? (spec 6, H3.)
///
/// It must match one of the document's listed URIs **exactly** — no prefix,
/// no scheme upgrade, no port wildcard. The one exception is the loopback
/// redirect of RFC 8252 §7.3, which Solid-OIDC's native clients defer to: a
/// `redirect_uri` with scheme `http`, host `127.0.0.1` or `[::1]`, and a path
/// byte-identical to a loopback URI the document *lists* matches regardless
/// of port. The document must list the loopback URI — the exception relaxes
/// the port, never the path, and never applies to a non-loopback URI.
pub fn allows_redirect(document: &ClientIdDocument, redirect_uri: &str) -> bool {
    document
        .redirect_uris
        .iter()
        .any(|listed| listed == redirect_uri || loopback_match(listed, redirect_uri))
}

/// The loopback half of [`allows_redirect`]: same URI, any port, both sides
/// loopback `http`.
fn loopback_match(listed: &str, requested: &str) -> bool {
    let (Ok(mut listed), Ok(mut requested)) = (Url::parse(listed), Url::parse(requested)) else {
        return false;
    };
    // Both must be loopback redirects, or the exception does not apply: it
    // never turns a listed non-loopback URI into a loopback match, and a
    // listed loopback URI never reaches out to some other host.
    if !is_loopback(&listed) || !is_loopback(&requested) {
        return false;
    }
    listed.set_port(None).is_ok() && requested.set_port(None).is_ok() && listed == requested
}

/// `http` on `127.0.0.1` or `[::1]`, the two loopback hosts RFC 8252 §7.3
/// names — exactly those, as the ATProto side's `is_loopback_host` also
/// insists. `localhost` by name is not one: it is a name for the transport's
/// address filter to judge, not a literal.
fn is_loopback(url: &Url) -> bool {
    url.scheme() == "http"
        && match url.host() {
            Some(Host::Ipv4(ip)) => ip == std::net::Ipv4Addr::LOCALHOST,
            Some(Host::Ipv6(ip)) => ip == std::net::Ipv6Addr::LOCALHOST,
            _ => false,
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: &str = "https://app.example/id";

    fn url() -> Url {
        Url::parse(CLIENT).unwrap()
    }

    /// A document, in Turtle: the form a hand-written one takes. `<>` cannot
    /// be used because the test documents carry their own subject line.
    fn turtle(body: &str) -> String {
        format!("@prefix oidc: <{}>.\n<{CLIENT}> {body}", vocab::SOLID_OIDC)
    }

    fn parsed(body: &str) -> Result<ClientIdDocument, InvalidDocument> {
        parse(&url(), "text/turtle", body.as_bytes())
    }

    #[test]
    fn a_correct_document_parses() {
        let document = parsed(&turtle(
            "oidc:redirect_uris <https://app.example/cb>, <http://127.0.0.1:3000/cb> ;\n\
             oidc:client_name \"Penny\" .",
        ))
        .unwrap();
        assert_eq!(document.client_id(), CLIENT);
        assert_eq!(document.client_name(), Some("Penny"));
        assert!(allows_redirect(&document, "https://app.example/cb"));
    }

    #[test]
    fn the_json_ld_form_parses_with_the_normative_context() {
        // The spec's own example shape (§5.1): JSON-LD referencing the
        // normative remote context. Without answering that context, no
        // conforming JSON-LD document could parse at all.
        let body = format!(
            r#"{{
                "@context": "{CONTEXT_URL}",
                "client_id": "{CLIENT}",
                "client_name": "Solid Application Name",
                "redirect_uris": ["https://app.example/callback", "http://127.0.0.1:8080/callback"]
            }}"#
        );
        let document = parse(&url(), "application/ld+json", body.as_bytes()).unwrap();
        assert_eq!(document.client_name(), Some("Solid Application Name"));
        assert!(allows_redirect(&document, "https://app.example/callback"));
        assert!(allows_redirect(&document, "http://127.0.0.1:1234/callback"));
    }

    #[test]
    fn a_document_without_the_client_own_triples_is_not_a_client() {
        // A profile, not a client: everything is about `#me`, nothing about
        // the client's own IRI.
        let profile = format!(
            "@prefix foaf: <{}>.\n<{}#me> foaf:name \"Alice\" .",
            vocab::FOAF,
            CLIENT
        );
        assert_eq!(parsed(&profile), Err(InvalidDocument::NotAClientDocument));
    }

    #[test]
    fn the_json_label_parses_as_json_ld() {
        // Penny's exact shape (observed 2026-10-06): the spec's own §5.1
        // example under the plain `application/json` label. The label is the
        // only nonconformance, and it is not one to break a finish-line
        // client over.
        let body = r#"{
                "@context": "https://www.w3.org/ns/solid/oidc-context.jsonld",
                "client_id": "https://penny.example/clientid.json",
                "client_name": "Penny",
                "redirect_uris": ["https://penny.example", "https://penny.example/"],
                "token_endpoint_auth_method": "none",
                "grant_types": ["refresh_token", "authorization_code"],
                "response_types": ["code"],
                "scope": "openid webid offline_access"
            }"#;
        let url = Url::parse("https://penny.example/clientid.json").unwrap();
        let document = parse(&url, "application/json", body.as_bytes()).unwrap();
        assert_eq!(document.client_id(), "https://penny.example/clientid.json");
        assert_eq!(document.client_name(), Some("Penny"));
        assert!(allows_redirect(&document, "https://penny.example"));
        assert!(allows_redirect(&document, "https://penny.example/"));
        assert!(!allows_redirect(&document, "https://attacker.example"));
        // Parameters on the label do not defeat the match either.
        assert!(parse(&url, "application/json; charset=utf-8", body.as_bytes()).is_ok());
    }

    #[test]
    fn a_plain_json_body_under_the_json_label_is_not_a_client() {
        // The label alone grants nothing: a body that is not the spec's JSON
        // form fails under `application/json` exactly as it would under
        // `application/ld+json` — here, by naming no redirect URIs.
        let body = r#"{"hello": "world"}"#;
        assert_eq!(
            parse(&url(), "application/json", body.as_bytes()),
            Err(InvalidDocument::NotAClientDocument)
        );
    }

    #[test]
    fn the_content_type_must_be_rdf_we_parse() {
        for content_type in ["text/html", "text/plain", ""] {
            assert_eq!(
                parse(&url(), content_type, b"<> a <https://example/Thing> ."),
                Err(InvalidDocument::NotRdf(content_type.to_string())),
                "{content_type} is not RDF"
            );
        }
        // Including `application/rdf+xml`: we serialize it but never parse it
        // (ADR 0007), and a fetched document is the untrusted input that rule
        // exists for.
        assert_eq!(
            parse(&url(), "application/rdf+xml", b"<x/>"),
            Err(InvalidDocument::NotRdf("application/rdf+xml".to_string()))
        );
        // Every RDF serialization we do parse passes the content-type check
        // and reaches the document ones — a document with no triples is
        // refused as not a client document, not as not RDF.
        for content_type in [
            "text/turtle",
            "application/n-triples",
            "application/n-quads",
            "application/trig",
        ] {
            assert_eq!(
                parse(&url(), content_type, b""),
                Err(InvalidDocument::NotAClientDocument),
                "{content_type} must pass the content-type check"
            );
        }
        // `{}` is the JSON-LD equivalent of an empty Turtle document.
        assert_eq!(
            parse(&url(), "application/ld+json", b"{}"),
            Err(InvalidDocument::NotAClientDocument)
        );
    }

    #[test]
    fn an_unparseable_body_is_refused() {
        assert!(matches!(
            parsed("this is not turtle"),
            Err(InvalidDocument::Unparseable(_))
        ));
    }

    #[test]
    fn a_json_ld_document_with_an_unknown_remote_context_is_refused() {
        // The parse must not fetch what a document tells it to: only the
        // spec's own context is answered, and only from the embedded bytes.
        let body = r#"{"@context": "https://attacker.example/context.jsonld"}"#;
        assert!(matches!(
            parse(&url(), "application/ld+json", body.as_bytes()),
            Err(InvalidDocument::Unparseable(_))
        ));
    }

    // --- redirect matching ---------------------------------------------------

    fn document_listing(uris: &[&str]) -> ClientIdDocument {
        let listed = uris
            .iter()
            .map(|u| format!("<{u}>"))
            .collect::<Vec<_>>()
            .join(", ");
        parsed(&turtle(&format!("oidc:redirect_uris {listed} .")))
            .unwrap_or_else(|e| panic!("a listing must parse: {e}"))
    }

    #[test]
    fn an_exact_redirect_uri_match_passes() {
        let document = document_listing(&["https://app.example/cb"]);
        assert!(allows_redirect(&document, "https://app.example/cb"));
    }

    #[test]
    fn prefix_matches_scheme_upgrades_and_port_wildcards_are_refused() {
        let document = document_listing(&["https://app.example/cb"]);
        for refused in [
            "https://app.example/cb/more", // a prefix is not the URI
            "https://app.example/cb?x=1",  // nor the URI plus a query
            "http://app.example/cb",       // no scheme upgrade, ever
            "https://app.example:8443/cb", // no port wildcard
            "https://app.example",         // nor the other direction
            "https://evil.example/cb",     // nor another host
        ] {
            assert!(
                !allows_redirect(&document, refused),
                "{refused} must not match"
            );
        }
    }

    #[test]
    fn a_loopback_redirect_matches_on_any_port_with_the_same_path() {
        let document = document_listing(&["http://127.0.0.1:3000/cb", "http://[::1]:3000/cb"]);
        for accepted in [
            "http://127.0.0.1:3000/cb",
            "http://127.0.0.1:49152/cb",
            "http://[::1]:1/cb",
        ] {
            assert!(
                allows_redirect(&document, accepted),
                "{accepted} must match"
            );
        }
    }

    #[test]
    fn a_loopback_redirect_with_a_different_path_is_refused() {
        let document = document_listing(&["http://127.0.0.1:3000/cb"]);
        assert!(!allows_redirect(&document, "http://127.0.0.1:3000/other"));
        assert!(!allows_redirect(
            &document,
            "http://127.0.0.1:3000/cb/longer"
        ));
    }

    #[test]
    fn the_loopback_exception_never_applies_to_a_non_loopback_uri() {
        // Listed non-loopback, requested loopback: no.
        let document = document_listing(&["https://app.example/cb"]);
        assert!(!allows_redirect(&document, "http://127.0.0.1:3000/cb"));
        // Listed loopback, requested non-loopback: no.
        let document = document_listing(&["http://127.0.0.1:3000/cb"]);
        assert!(!allows_redirect(&document, "https://app.example/cb"));
        assert!(!allows_redirect(&document, "http://localhost:3000/cb"));
    }

    #[test]
    fn an_unlisted_loopback_redirect_is_refused() {
        // The document lists no loopback URI at all.
        let document = document_listing(&["https://app.example/cb"]);
        assert!(!allows_redirect(&document, "http://127.0.0.1:9999/cb"));
    }

    #[test]
    fn a_collection_of_redirect_uris_is_read_like_a_set() {
        // Hand-written Turtle may hang a collection off the predicate; the
        // URIs are the document's either way.
        let document = parsed(&turtle(
            "oidc:redirect_uris ( <https://app.example/cb> <http://127.0.0.1:3000/cb> ) .",
        ))
        .unwrap();
        assert!(allows_redirect(&document, "https://app.example/cb"));
        assert!(allows_redirect(&document, "http://127.0.0.1:4000/cb"));
    }
}
