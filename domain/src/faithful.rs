//! The faithful layer: lossless JSON ⇄ quads.
//!
//! Every protocol write lands here first, always, with no mapping table and no
//! knowledge of the schema. That is what makes "export" complete — a user's
//! dump contains everything any protocol ever wrote, including lexicons nobody
//! has seen.
//!
//! The predecessor stashed the original JSON in a `mycorriza:rawJson` literal
//! beside the triples, because nothing guaranteed the triples could reconstruct
//! the wire format. The property test in `tests/roundtrip.rs` is that
//! guarantee, and it is why this codebase has no `rawJson`.
//!
//! Encoding rules, all reversible:
//!
//! | JSON | RDF |
//! |---|---|
//! | object | subject node, `rdf:type brolly:JsonObject`, one predicate per key |
//! | array | `rdf:List` (`rdf:first`/`rdf:rest`/`rdf:nil`) — preserves order |
//! | string | plain literal (`xsd:string`) |
//! | integer | `xsd:integer` |
//! | float | `xsd:double`, shortest round-trip form |
//! | bool | `xsd:boolean` |
//! | null | the IRI `brolly:null` |

use oxrdf::{BlankNode, GraphName, Literal, NamedNode, NamedOrBlankNode, Quad, Term};
use serde_json::{Map, Value};

use crate::{nsid, vocab};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaithfulError {
    /// The record has no `$type`, so there is no namespace to key fields under.
    MissingType,
    NotAnObject,
    Malformed(String),
}

impl std::fmt::Display for FaithfulError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FaithfulError::MissingType => write!(f, "record has no $type"),
            FaithfulError::NotAnObject => write!(f, "record is not a JSON object"),
            FaithfulError::Malformed(m) => write!(f, "malformed graph: {m}"),
        }
    }
}

impl std::error::Error for FaithfulError {}

fn iri(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

fn typed(value: impl Into<String>, datatype: &str) -> Term {
    Term::Literal(Literal::new_typed_literal(value, iri(datatype)))
}

/// Encode a record into quads rooted at `subject`, in graph `graph`.
///
/// `lexicon` names the term space for field predicates. For ATProtocol that is
/// the record's `$type`; for AS2 the caller passes the AS2 namespace marker so
/// fields land on the standard vocabulary instead.
pub fn encode(
    record: &Value,
    subject: &NamedNode,
    graph: &NamedNode,
    lexicon: &str,
) -> Result<Vec<Quad>, FaithfulError> {
    let obj = record.as_object().ok_or(FaithfulError::NotAnObject)?;
    let mut quads = Vec::new();
    let graph_name = GraphName::NamedNode(graph.clone());

    quads.push(Quad::new(
        NamedOrBlankNode::NamedNode(subject.clone()),
        iri(vocab::LEXICON),
        Term::Literal(Literal::new_simple_literal(lexicon)),
        graph_name.clone(),
    ));

    encode_object(
        obj,
        &NamedOrBlankNode::NamedNode(subject.clone()),
        lexicon,
        &graph_name,
        &mut quads,
    );
    Ok(quads)
}

fn encode_object(
    obj: &Map<String, Value>,
    subject: &NamedOrBlankNode,
    lexicon: &str,
    graph: &GraphName,
    out: &mut Vec<Quad>,
) {
    out.push(Quad::new(
        subject.clone(),
        iri(vocab::RDF_TYPE),
        Term::NamedNode(iri(vocab::JSON_OBJECT)),
        graph.clone(),
    ));

    for (key, value) in obj {
        let predicate = iri(&nsid::predicate(lexicon, key));
        let term = encode_value(value, lexicon, graph, out);
        out.push(Quad::new(subject.clone(), predicate, term, graph.clone()));
    }
}

fn encode_value(value: &Value, lexicon: &str, graph: &GraphName, out: &mut Vec<Quad>) -> Term {
    match value {
        Value::Null => Term::NamedNode(iri(vocab::JSON_NULL)),
        Value::Bool(b) => typed(b.to_string(), vocab::XSD_BOOLEAN),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                typed(i.to_string(), vocab::XSD_INTEGER)
            } else if let Some(u) = n.as_u64() {
                typed(u.to_string(), vocab::XSD_INTEGER)
            } else if let Some(f) = n.as_f64() {
                // `{:?}` is Rust's shortest round-trip form and keeps the `.0`
                // that distinguishes 1.0 from 1.
                typed(format!("{f:?}"), vocab::XSD_DOUBLE)
            } else {
                typed(n.to_string(), vocab::XSD_DOUBLE)
            }
        }
        Value::String(s) => Term::Literal(Literal::new_simple_literal(s)),
        Value::Array(items) => encode_list(items, lexicon, graph, out),
        Value::Object(map) => {
            let node = BlankNode::default();
            encode_object(
                map,
                &NamedOrBlankNode::BlankNode(node.clone()),
                lexicon,
                graph,
                out,
            );
            Term::BlankNode(node)
        }
    }
}

fn encode_list(items: &[Value], lexicon: &str, graph: &GraphName, out: &mut Vec<Quad>) -> Term {
    let Some((head, tail)) = items.split_first() else {
        return Term::NamedNode(iri(vocab::RDF_NIL));
    };
    let node = BlankNode::default();
    let head_term = encode_value(head, lexicon, graph, out);
    out.push(Quad::new(
        NamedOrBlankNode::BlankNode(node.clone()),
        iri(vocab::RDF_FIRST),
        head_term,
        graph.clone(),
    ));
    let rest = encode_list(tail, lexicon, graph, out);
    out.push(Quad::new(
        NamedOrBlankNode::BlankNode(node.clone()),
        iri(vocab::RDF_REST),
        rest,
        graph.clone(),
    ));
    Term::BlankNode(node)
}

/// Decode quads back into the original record.
pub fn decode(quads: &[Quad], subject: &NamedNode) -> Result<Value, FaithfulError> {
    let lexicon = quads
        .iter()
        .find(|q| {
            q.subject == NamedOrBlankNode::NamedNode(subject.clone())
                && q.predicate.as_str() == vocab::LEXICON
        })
        .and_then(|q| match &q.object {
            Term::Literal(l) => Some(l.value().to_string()),
            _ => None,
        })
        .ok_or(FaithfulError::MissingType)?;

    decode_object(
        quads,
        &NamedOrBlankNode::NamedNode(subject.clone()),
        &lexicon,
    )
}

fn decode_object(
    quads: &[Quad],
    subject: &NamedOrBlankNode,
    lexicon: &str,
) -> Result<Value, FaithfulError> {
    let mut map = Map::new();
    for quad in quads.iter().filter(|q| &q.subject == subject) {
        if quad.predicate.as_str() == vocab::RDF_TYPE || quad.predicate.as_str() == vocab::LEXICON {
            continue;
        }
        let Some((_, field)) = nsid::split(quad.predicate.as_str()) else {
            continue;
        };
        map.insert(
            field.to_string(),
            decode_term(quads, &quad.object, lexicon)?,
        );
    }
    Ok(Value::Object(map))
}

fn decode_term(quads: &[Quad], term: &Term, lexicon: &str) -> Result<Value, FaithfulError> {
    match term {
        Term::NamedNode(n) if n.as_str() == vocab::JSON_NULL => Ok(Value::Null),
        Term::NamedNode(n) if n.as_str() == vocab::RDF_NIL => Ok(Value::Array(Vec::new())),
        Term::NamedNode(n) => Ok(Value::String(n.as_str().to_string())),
        Term::Literal(l) => decode_literal(l),
        Term::BlankNode(b) => {
            let subject = NamedOrBlankNode::BlankNode(b.clone());
            if is_list_node(quads, &subject) {
                decode_list(quads, &subject, lexicon)
            } else {
                decode_object(quads, &subject, lexicon)
            }
        }
    }
}

fn decode_literal(literal: &Literal) -> Result<Value, FaithfulError> {
    let value = literal.value();
    match literal.datatype().as_str() {
        vocab::XSD_BOOLEAN => Ok(Value::Bool(value == "true")),
        vocab::XSD_INTEGER => value
            .parse::<i64>()
            .map(Value::from)
            .or_else(|_| value.parse::<u64>().map(Value::from))
            .map_err(|e| FaithfulError::Malformed(format!("integer {value}: {e}"))),
        vocab::XSD_DOUBLE => value
            .parse::<f64>()
            .map(Value::from)
            .map_err(|e| FaithfulError::Malformed(format!("double {value}: {e}"))),
        _ => Ok(Value::String(value.to_string())),
    }
}

fn is_list_node(quads: &[Quad], subject: &NamedOrBlankNode) -> bool {
    quads
        .iter()
        .any(|q| &q.subject == subject && q.predicate.as_str() == vocab::RDF_FIRST)
}

fn decode_list(
    quads: &[Quad],
    subject: &NamedOrBlankNode,
    lexicon: &str,
) -> Result<Value, FaithfulError> {
    let mut items = Vec::new();
    let mut cursor = subject.clone();
    loop {
        let Some(first) = quads
            .iter()
            .find(|q| q.subject == cursor && q.predicate.as_str() == vocab::RDF_FIRST)
        else {
            break;
        };
        items.push(decode_term(quads, &first.object, lexicon)?);

        let Some(rest) = quads
            .iter()
            .find(|q| q.subject == cursor && q.predicate.as_str() == vocab::RDF_REST)
        else {
            break;
        };
        match &rest.object {
            Term::BlankNode(b) => cursor = NamedOrBlankNode::BlankNode(b.clone()),
            _ => break,
        }
    }
    Ok(Value::Array(items))
}

/// Convenience: the subject and graph a record occupies, given its resource IRI.
pub fn resource_nodes(resource_iri: &str) -> (NamedNode, NamedNode) {
    (iri(resource_iri), iri(resource_iri))
}
