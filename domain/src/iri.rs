//! IRI canonicalization, applied at exactly one choke point.
//!
//! The same vocabulary is published under more than one IRI in the wild — AS2
//! exists as both `http://www.w3.org/ns/activitystreams#` and the `https`
//! form, and senders use whichever they were built against. The predecessor
//! stored whichever arrived, so five separate reader modules had to match both
//! spellings and a production bug shipped when one of them only matched the
//! `http` variant.
//!
//! Every quad is normalized on the way in. A test asserts no stored quad uses a
//! non-canonical namespace, so the ambiguity cannot re-enter through a new
//! writer.

use oxrdf::{NamedNode, NamedOrBlankNode, Quad, Term};

/// Alias → canonical. Longest-prefix wins, so order within the table does not
/// matter but overlapping prefixes must be listed most-specific first.
const ALIASES: &[(&str, &str)] = &[
    // AS2: the http spelling is the one Mastodon and much of the fediverse emit.
    (
        "http://www.w3.org/ns/activitystreams#",
        "https://www.w3.org/ns/activitystreams#",
    ),
    // Security vocabulary: v1 and v2 context IRIs both appear on actor documents.
    (
        "https://w3id.org/security/v2#",
        "https://w3id.org/security#",
    ),
    (
        "https://w3id.org/security/v1#",
        "https://w3id.org/security#",
    ),
    ("https://w3id.org/security/v1", "https://w3id.org/security#"),
    // Mastodon's extension namespace is published over http.
    (
        "https://joinmastodon.org/ns#",
        "http://joinmastodon.org/ns#",
    ),
];

/// Rewrite an IRI to its canonical namespace. Unknown IRIs pass through.
pub fn canonicalize(iri: &str) -> String {
    for (alias, canonical) in ALIASES {
        if let Some(rest) = iri.strip_prefix(alias) {
            return format!("{canonical}{rest}");
        }
    }
    iri.to_string()
}

/// True if `iri` is already canonical.
pub fn is_canonical(iri: &str) -> bool {
    !ALIASES.iter().any(|(alias, _)| iri.starts_with(alias))
}

fn canonicalize_node(node: &NamedNode) -> NamedNode {
    let canonical = canonicalize(node.as_str());
    if canonical == node.as_str() {
        node.clone()
    } else {
        NamedNode::new_unchecked(canonical)
    }
}

fn canonicalize_subject(subject: &NamedOrBlankNode) -> NamedOrBlankNode {
    match subject {
        NamedOrBlankNode::NamedNode(n) => NamedOrBlankNode::NamedNode(canonicalize_node(n)),
        other => other.clone(),
    }
}

fn canonicalize_term(term: &Term) -> Term {
    match term {
        Term::NamedNode(n) => Term::NamedNode(canonicalize_node(n)),
        other => other.clone(),
    }
}

/// Normalize every IRI position in a quad. This is the choke point — call it on
/// the way into storage and nowhere else.
pub fn canonicalize_quad(quad: &Quad) -> Quad {
    Quad {
        subject: canonicalize_subject(&quad.subject),
        predicate: canonicalize_node(&quad.predicate),
        object: canonicalize_term(&quad.object),
        graph_name: match &quad.graph_name {
            oxrdf::GraphName::NamedNode(n) => oxrdf::GraphName::NamedNode(canonicalize_node(n)),
            other => other.clone(),
        },
    }
}

/// Every IRI appearing anywhere in a quad. Used by the invariant test.
pub fn iris_in(quad: &Quad) -> Vec<&str> {
    let mut out = Vec::new();
    if let NamedOrBlankNode::NamedNode(n) = &quad.subject {
        out.push(n.as_str());
    }
    out.push(quad.predicate.as_str());
    match &quad.object {
        Term::NamedNode(n) => out.push(n.as_str()),
        Term::Literal(l) => out.push(l.datatype().as_str()),
        _ => {}
    }
    if let oxrdf::GraphName::NamedNode(n) = &quad.graph_name {
        out.push(n.as_str());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as2_http_becomes_https() {
        assert_eq!(
            canonicalize("http://www.w3.org/ns/activitystreams#Note"),
            "https://www.w3.org/ns/activitystreams#Note"
        );
    }

    #[test]
    fn canonical_form_is_stable() {
        let canonical = "https://www.w3.org/ns/activitystreams#Note";
        assert_eq!(canonicalize(canonical), canonical);
        assert!(is_canonical(canonical));
    }

    #[test]
    fn security_v1_and_v2_collapse() {
        assert_eq!(
            canonicalize("https://w3id.org/security/v1#publicKey"),
            "https://w3id.org/security#publicKey"
        );
        assert_eq!(
            canonicalize("https://w3id.org/security/v2#publicKey"),
            "https://w3id.org/security#publicKey"
        );
    }

    #[test]
    fn unknown_iris_pass_through() {
        let iri = "https://example.com/vocab#thing";
        assert_eq!(canonicalize(iri), iri);
    }

    #[test]
    fn the_http_variant_is_not_canonical() {
        assert!(!is_canonical("http://www.w3.org/ns/activitystreams#Note"));
    }
}
