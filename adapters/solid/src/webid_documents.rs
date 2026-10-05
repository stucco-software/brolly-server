//! WebID profile documents, dereferenced (spec 6, H5).
//!
//! The issuer-binding half of the remote path: a token from another
//! Solid-OIDC issuer is only trusted for the WebID it names once the WebID's
//! own document says that issuer may speak for it — `solid:oidcIssuer`, the
//! triple that exists for exactly this. Without the binding, anyone who can
//! serve HTTPS can publish a discovery document and a key set, and "which
//! issuers may speak for WebID W" becomes "all of them".
//!
//! The fetching — the same hardened transport a Client ID Document rides,
//! with the same RDF [`Accept`][client_documents::ACCEPT] — lives in
//! `brolly_server`, parameterized by [`WebIdDocument`]; everything here is
//! what varies with the protocol: the content-type check, the parse, and the
//! membership check the binding is.
//!
//! The fetch URL is the WebID itself, fragment included. The fragment never
//! reaches the wire — an HTTP request target has none — and keeping it in the
//! URL means the parse can anchor on the WebID's exact IRI, which is the
//! point: the binding is the WebID's own assertion, not the document's, so a
//! `solid:oidcIssuer` triple about some other node in the document is not
//! read.

use brolly_domain::syntax::{self, ReadFormat};
use brolly_domain::vocab;
use oxigraph::io::{JsonLdProfileSet, RdfFormat, RdfParser};
use oxigraph::model::{NamedNode, NamedOrBlankNode, Quad, Term};
use url::Url;

/// Why fetched bytes are not a usable WebID profile document (spec 6, H5).
///
/// Every message names the rule, never anything fetched: the operator's log
/// gets the detail, and the caller — an unauthenticated one, on the pod
/// surface — gets one answer for every cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidWebIdDocument {
    /// Served as something RDF is not served as. Our own `/profile` serves
    /// HTML to anything that sounds like a browser, so a fetch that does not
    /// ask for RDF gets a page — this is the refusal that catches it.
    NotRdf(String),
    /// The body did not parse as its content type claimed.
    Unparseable(String),
}

impl std::fmt::Display for InvalidWebIdDocument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidWebIdDocument::NotRdf(content_type) => write!(
                f,
                "a WebID profile document must be served as RDF, not {content_type}"
            ),
            InvalidWebIdDocument::Unparseable(e) => {
                write!(f, "the WebID profile document did not parse: {e}")
            }
        }
    }
}

impl std::error::Error for InvalidWebIdDocument {}

/// A WebID's profile document (spec 6, H5), as the issuer binding reads it:
/// the `solid:oidcIssuer` values on the WebID's own IRI, and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebIdDocument {
    issuers: Vec<String>,
}

impl WebIdDocument {
    /// Does the WebID name this issuer among its `solid:oidcIssuer` values?
    /// (spec 6, H5)
    ///
    /// `false` is a refusal the caller maps to the same 401 as every other
    /// remote failure: a WebID that names no such issuer is one whose claim
    /// of identity cannot be verified — and a local WebID is one that can
    /// never name a foreign issuer, since H1 makes that triple
    /// server-authoritative and this instance writes its own apex there.
    pub fn names(&self, issuer: &str) -> bool {
        self.issuers.iter().any(|named| named == issuer)
    }
}

/// Parse the profile document at `webid` (spec 6, H5): the content-type check
/// and the RDF parse the fetch is parameterized with.
///
/// `webid` is the fetch URL — the WebID with its fragment, which the wire
/// never sees — and it is both the base IRI relative IRIs resolve against and
/// the subject whose `solid:oidcIssuer` triples are read, so a hand-written
/// `<#me> solid:oidcIssuer <...>` names the WebID and nothing else does.
pub fn parse(
    webid: &Url,
    content_type: &str,
    body: &[u8],
) -> Result<WebIdDocument, InvalidWebIdDocument> {
    let format = syntax::read_format(content_type)
        .map_err(|_| InvalidWebIdDocument::NotRdf(content_type.to_string()))?;
    // `application/rdf+xml` is a `NotRdf` too, by design: we serialize it but
    // never parse it (ADR 0007), and a fetched document is exactly the
    // untrusted input that rule exists for.
    let quads = match format {
        ReadFormat::JsonLd => json_ld(webid, body)?,
        other => syntax::parse(body, other, webid.as_str())
            .map_err(|e| InvalidWebIdDocument::Unparseable(e.to_string()))?,
    };

    let subject = NamedOrBlankNode::NamedNode(NamedNode::new_unchecked(webid.as_str()));
    let mut issuers = Vec::new();
    for quad in &quads {
        if quad.subject != subject || quad.predicate.as_str() != vocab::SOLID_OIDC_ISSUER {
            continue;
        }
        // A literal or blank node is not an issuer anyone can name; it is
        // skipped rather than refused, like a key the set cannot use.
        if let Term::NamedNode(issuer) = &quad.object {
            issuers.push(issuer.as_str().to_owned());
        }
    }
    Ok(WebIdDocument { issuers })
}

/// A JSON-LD parse that answers no remote context (spec 6, H5).
///
/// Unlike a Client ID Document, a WebID profile has no normative context to
/// embed — so a document that references one is not a document we can read,
/// and the parse says so rather than fetching it: a parse must not do I/O,
/// and a document's choice of context must not turn into a URL we fetch.
/// JSON-LD with an inline context or absolute IRIs needs no remote context
/// and parses.
fn json_ld(webid: &Url, body: &[u8]) -> Result<Vec<Quad>, InvalidWebIdDocument> {
    RdfParser::from_format(RdfFormat::JsonLd {
        profile: JsonLdProfileSet::empty(),
    })
    .with_base_iri(webid.as_str())
    .map_err(|e| InvalidWebIdDocument::Unparseable(e.to_string()))?
    .for_slice(body)
    .with_document_loader(|url| {
        Err(format!("remote context {url} is not a context we can read").into())
    })
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| InvalidWebIdDocument::Unparseable(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WEBID: &str = "https://bob.example.org/profile#me";
    const ISSUER: &str = "https://idp.example";
    const SOLID: &str = "http://www.w3.org/ns/solid/terms#oidcIssuer";

    fn parsed(turtle: &str) -> WebIdDocument {
        parse(
            &Url::parse(WEBID).unwrap(),
            "text/turtle",
            turtle.as_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn a_profile_naming_its_issuer_parses() {
        let document = parsed(&format!(
            "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n\
             <{WEBID}> solid:oidcIssuer <{ISSUER}> ."
        ));
        assert!(document.names(ISSUER));
        assert!(!document.names("https://other-idp.example"));
    }

    #[test]
    fn a_relative_subject_resolves_to_the_webid() {
        // The load-bearing parse detail: the fetch URL carries the fragment,
        // and `<#me>` must resolve against its path to the WebID — the exact
        // IRI the binding matches — never to the bare document.
        let document = parsed(&format!("@prefix : <#>.\n:me <{SOLID}> <{ISSUER}> ."));
        assert!(document.names(ISSUER));
    }

    #[test]
    fn the_webid_owns_the_assertion() {
        // `solid:oidcIssuer` on any other node in the document is not the
        // WebID's: without the exact-subject anchor, a profile could vouch
        // for its issuer by quoting someone else's triple.
        let document = parsed(&format!(
            "<https://elsewhere.example/#someone> <{SOLID}> <{ISSUER}> ."
        ));
        assert!(!document.names(ISSUER));
    }

    #[test]
    fn a_profile_may_name_several_issuers() {
        let document = parsed(&format!(
            "<{WEBID}> <{SOLID}> <https://one.example>, <https://two.example> ."
        ));
        assert!(document.names("https://one.example"));
        assert!(document.names("https://two.example"));
        assert!(!document.names(ISSUER));
    }

    #[test]
    fn the_content_type_must_be_rdf_we_parse() {
        let webid = Url::parse(WEBID).unwrap();
        for content_type in ["text/html", "application/json", "application/rdf+xml"] {
            let refused = parse(&webid, content_type, b"<a> <b> <c> .");
            assert!(
                matches!(refused, Err(InvalidWebIdDocument::NotRdf(_))),
                "{content_type} was parsed"
            );
        }
    }

    #[test]
    fn an_unparseable_body_is_refused() {
        assert!(matches!(
            parse(
                &Url::parse(WEBID).unwrap(),
                "text/turtle",
                b"this is not turtle {{{"
            ),
            Err(InvalidWebIdDocument::Unparseable(_))
        ));
    }

    #[test]
    fn a_json_ld_document_with_a_remote_context_is_refused() {
        // No normative context to embed (H5), so a remote one is a document
        // we cannot read — never a URL to fetch inside a parse.
        let body = format!(
            r#"{{"@context": "https://www.w3.org/ns/solid/context.jsonld",
                 "@id": "{WEBID}", "solid:oidcIssuer": "{ISSUER}"}}"#
        );
        assert!(matches!(
            parse(
                &Url::parse(WEBID).unwrap(),
                "application/ld+json",
                body.as_bytes()
            ),
            Err(InvalidWebIdDocument::Unparseable(_))
        ));
    }

    #[test]
    fn a_json_ld_document_needing_no_context_parses() {
        let body = format!(
            r#"[{{"@id": "{WEBID}",
                 "http://www.w3.org/ns/solid/terms#oidcIssuer": {{"@id": "{ISSUER}"}}}}]"#
        );
        let document = parse(
            &Url::parse(WEBID).unwrap(),
            "application/ld+json",
            body.as_bytes(),
        )
        .unwrap();
        assert!(document.names(ISSUER));
    }
}
