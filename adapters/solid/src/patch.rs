//! `PATCH`: N3 Patch and SPARQL Update, through **one** solver.
//!
//! The predecessor accepted both content types and implemented them twice — the
//! SPARQL path delegated to the engine while N3 Patch got a hand-rolled parser
//! and pattern solver, 909 lines with its own bindings table. Two
//! implementations of the same semantics is two sets of bugs.
//!
//! Here N3 Patch is *translated* into SPARQL Update and both run through
//! oxigraph. That is possible because oxttl parses N3 formulae, encoding each
//! `{ … }` as a distinct blank-node graph — so the three formulae of a patch
//! come back as three addressable graphs and no bespoke parser is needed.
//!
//! Preconditions are the part SPARQL cannot express. `DELETE/INSERT/WHERE`
//! silently succeeds when nothing matches, whereas Solid requires a patch to
//! *fail* if `solid:where` does not bind or a `solid:deletes` triple is absent.
//! Those are checked first, so a client is never told a patch applied when it
//! did not.

use brolly_store::resources::{PodRead, PodWrite};
use oxigraph::model::{GraphNameRef, NamedNode, Quad};
use oxigraph::sparql::SparqlEvaluator;
use oxigraph::store::Store;
use oxttl::N3Parser;
use oxttl::n3::{N3Quad, N3Term};

const SOLID: &str = "http://www.w3.org/ns/solid/terms#";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

#[derive(Debug)]
pub enum PatchError {
    /// Body did not parse.
    Malformed(String),
    /// Parsed, but is not an `InsertDeletePatch` with usable formulae.
    NotAPatch(String),
    /// `solid:where` matched nothing, or a `solid:deletes` triple was absent.
    /// Solid maps this to `409 Conflict` — the patch is well-formed but the
    /// document is not in the state it assumed.
    Precondition(String),
    /// A SPARQL Update that would escape the resource's own graph.
    EscapesGraph,
    Store(String),
}

impl std::fmt::Display for PatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatchError::Malformed(e) => write!(f, "malformed patch: {e}"),
            PatchError::NotAPatch(e) => write!(f, "not an InsertDeletePatch: {e}"),
            PatchError::Precondition(e) => write!(f, "precondition failed: {e}"),
            PatchError::EscapesGraph => write!(
                f,
                "SPARQL Update may not name a GRAPH or WITH — a PATCH acts on \
                 the resource it addresses"
            ),
            PatchError::Store(e) => write!(f, "storage: {e}"),
        }
    }
}

impl std::error::Error for PatchError {}

/// The three formulae of an N3 Patch, as triple patterns.
#[derive(Debug, Default)]
pub struct N3Patch {
    pub where_clause: Vec<[N3Term; 3]>,
    pub deletes: Vec<[N3Term; 3]>,
    pub inserts: Vec<[N3Term; 3]>,
}

/// Parse an N3 Patch document.
pub fn parse_n3_patch(body: &[u8], base: &str) -> Result<N3Patch, PatchError> {
    let quads: Vec<N3Quad> = N3Parser::new()
        .with_base_iri(base)
        .map_err(|e| PatchError::Malformed(e.to_string()))?
        .for_slice(body)
        .collect::<Result<_, _>>()
        .map_err(|e| PatchError::Malformed(e.to_string()))?;

    // The patch node declares itself; its predicates name the formula graphs.
    let patch_node = quads
        .iter()
        .find(|q| {
            matches!(&q.predicate, N3Term::NamedNode(p) if p.as_str() == RDF_TYPE)
                && matches!(&q.object, N3Term::NamedNode(o)
                    if o.as_str() == format!("{SOLID}InsertDeletePatch"))
        })
        .map(|q| q.subject.clone())
        .ok_or_else(|| PatchError::NotAPatch("no solid:InsertDeletePatch".into()))?;

    let mut patch = N3Patch::default();
    for quad in &quads {
        if quad.subject != patch_node {
            continue;
        }
        let N3Term::NamedNode(predicate) = &quad.predicate else {
            continue;
        };
        let target = match predicate.as_str().strip_prefix(SOLID) {
            Some("where") => &mut patch.where_clause,
            Some("deletes") => &mut patch.deletes,
            Some("inserts") => &mut patch.inserts,
            _ => continue,
        };
        // The object is the blank node oxttl used to name the formula's graph.
        let N3Term::BlankNode(formula) = &quad.object else {
            return Err(PatchError::NotAPatch(
                "solid:where/deletes/inserts must be a formula".into(),
            ));
        };
        *target = triples_in_formula(&quads, formula.as_str());
    }

    if patch.deletes.is_empty() && patch.inserts.is_empty() {
        return Err(PatchError::NotAPatch("patch does nothing".into()));
    }
    Ok(patch)
}

fn triples_in_formula(quads: &[N3Quad], formula: &str) -> Vec<[N3Term; 3]> {
    quads
        .iter()
        .filter(|q| match &q.graph_name {
            oxigraph::model::GraphName::BlankNode(b) => b.as_str() == formula,
            _ => false,
        })
        .map(|q| [q.subject.clone(), q.predicate.clone(), q.object.clone()])
        .collect()
}

/// Render an N3 term as SPARQL syntax.
fn term_to_sparql(term: &N3Term) -> String {
    match term {
        N3Term::NamedNode(n) => format!("<{}>", n.as_str()),
        N3Term::BlankNode(b) => format!("_:{}", b.as_str()),
        N3Term::Literal(l) => l.to_string(),
        N3Term::Variable(v) => format!("?{}", v.as_str()),
    }
}

fn patterns_to_sparql(patterns: &[[N3Term; 3]]) -> String {
    patterns
        .iter()
        .map(|[s, p, o]| {
            format!(
                "  {} {} {} .",
                term_to_sparql(s),
                term_to_sparql(p),
                term_to_sparql(o)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Translate a parsed N3 Patch into a SPARQL Update.
///
/// No graph is named: the update runs against a scratch store whose *default*
/// graph holds the resource, so the resource scoping is structural rather than
/// syntactic. See [`apply_scoped`].
pub fn n3_patch_to_sparql(patch: &N3Patch) -> String {
    let mut update = String::new();
    if !patch.deletes.is_empty() {
        update.push_str(&format!(
            "DELETE {{\n{}\n}}\n",
            patterns_to_sparql(&patch.deletes)
        ));
    }
    if !patch.inserts.is_empty() {
        update.push_str(&format!(
            "INSERT {{\n{}\n}}\n",
            patterns_to_sparql(&patch.inserts)
        ));
    }
    // WHERE is mandatory in DELETE/INSERT form; an empty one matches once,
    // which is the right semantics for an unconditional patch.
    update.push_str(&format!(
        "WHERE {{\n{}\n}}",
        patterns_to_sparql(&patch.where_clause)
    ));
    update
}

/// Does a SPARQL Update stay inside the resource it addresses?
///
/// A PATCH acts on one resource. An update naming `GRAPH` or `WITH` could reach
/// elsewhere in the pod, so it is refused rather than rewritten — silently
/// re-scoping someone's query would be worse than saying no.
pub fn is_graph_safe(sparql: &str) -> bool {
    let upper = sparql.to_uppercase();
    !upper.contains("GRAPH") && !upper.contains("WITH")
}

/// Run an update against one resource, in isolation.
///
/// The resource's triples are copied into a scratch in-memory store as its
/// **default graph**, the update runs there verbatim, and the result replaces
/// the resource's named graph inside the caller's write.
///
/// This avoids rewriting the client's SPARQL. Wrapping text in `WITH <g>` only
/// works for the `DELETE/INSERT … WHERE` form — `INSERT DATA`, which is what
/// most Solid clients actually send, needs `GRAPH <g> { … }` inside the braces
/// instead. Doing that by string surgery on a user-supplied query is exactly
/// the kind of parser-by-regex this codebase should not contain.
///
/// Two properties fall out for free: the result goes through the pod's
/// canonicalising write path, so IRIs are canonicalized like any other write
/// rather than needing a fix-up pass afterwards; and the swap is computed
/// before it is applied, so a failing update leaves the resource untouched.
fn apply_scoped(
    w: &mut PodWrite<'_>,
    resource: &str,
    update: &str,
    precondition: impl Fn(&Store) -> Result<(), PatchError>,
) -> Result<(), PatchError> {
    let graph = NamedNode::new_unchecked(resource);

    let scratch = Store::new().map_err(|e| PatchError::Store(e.to_string()))?;
    for quad in w.quads_for_pattern(
        None,
        None,
        None,
        Some(GraphNameRef::NamedNode(graph.as_ref())),
    ) {
        let quad = quad.map_err(|e| PatchError::Store(e.to_string()))?;
        scratch
            .insert(&Quad::new(
                quad.subject,
                quad.predicate,
                quad.object,
                oxigraph::model::GraphName::DefaultGraph,
            ))
            .map_err(|e| PatchError::Store(e.to_string()))?;
    }

    precondition(&scratch)?;
    run_update(&scratch, update)?;

    let patched: Vec<Quad> = scratch
        .quads_for_pattern(None, None, None, Some(GraphNameRef::DefaultGraph))
        .filter_map(Result::ok)
        .map(|q| Quad::new(q.subject, q.predicate, q.object, graph.clone()))
        .collect();

    // Every PATCH target is under the storage root (`pod.rs` refuses the rest).
    w.legacy_under_root()
        .replace_graph(resource, &patched)
        .map_err(|e| PatchError::Store(e.to_string()))?;
    Ok(())
}

/// Check the preconditions SPARQL cannot express.
///
/// `DELETE/INSERT/WHERE` silently succeeds when nothing matches, whereas Solid
/// requires a patch to *fail* if `solid:where` does not bind or a
/// `solid:deletes` triple is absent. Without this a client would be told a
/// patch applied when it did not.
fn check_preconditions(scratch: &Store, patch: &N3Patch) -> Result<(), PatchError> {
    if !patch.where_clause.is_empty() {
        let ask = format!("ASK {{\n{}\n}}", patterns_to_sparql(&patch.where_clause));
        if !ask_query(scratch, &ask)? {
            return Err(PatchError::Precondition(
                "solid:where matched nothing".into(),
            ));
        }
    }

    // Every deleted triple must already exist. Ground triples are checked
    // directly; ones containing variables are covered by the where clause.
    for pattern in &patch.deletes {
        if pattern.iter().any(|t| matches!(t, N3Term::Variable(_))) {
            continue;
        }
        let ask = format!(
            "ASK {{\n{}\n}}",
            patterns_to_sparql(std::slice::from_ref(pattern))
        );
        if !ask_query(scratch, &ask)? {
            return Err(PatchError::Precondition(
                "a solid:deletes triple is not present".into(),
            ));
        }
    }
    Ok(())
}

fn ask_query(store: &Store, query: &str) -> Result<bool, PatchError> {
    let results = SparqlEvaluator::new()
        .parse_query(query)
        .map_err(|e| PatchError::Store(e.to_string()))?
        .on_store(store)
        .execute()
        .map_err(|e| PatchError::Store(e.to_string()))?;
    match results {
        oxigraph::sparql::QueryResults::Boolean(b) => Ok(b),
        _ => Err(PatchError::Store("expected an ASK result".into())),
    }
}

fn run_update(store: &Store, update: &str) -> Result<(), PatchError> {
    SparqlEvaluator::new()
        .parse_update(update)
        .map_err(|e| PatchError::Store(e.to_string()))?
        .on_store(store)
        .execute()
        .map_err(|e| PatchError::Store(e.to_string()))
}

/// Apply an N3 Patch to a resource, inside the caller's write.
pub fn apply_n3_patch(w: &mut PodWrite<'_>, resource: &str, body: &[u8]) -> Result<(), PatchError> {
    let patch = parse_n3_patch(body, resource)?;
    let update = n3_patch_to_sparql(&patch);
    apply_scoped(w, resource, &update, |scratch| {
        check_preconditions(scratch, &patch)
    })
}

/// Apply a SPARQL Update to a resource, inside the caller's write.
pub fn apply_sparql_update(
    w: &mut PodWrite<'_>,
    resource: &str,
    sparql: &str,
) -> Result<(), PatchError> {
    if !is_graph_safe(sparql) {
        return Err(PatchError::EscapesGraph);
    }
    apply_scoped(w, resource, sparql, |_| Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_safety_rejects_scope_escapes() {
        assert!(is_graph_safe("INSERT DATA { <a> <b> <c> }"));
        assert!(!is_graph_safe("INSERT DATA { GRAPH <g> { <a> <b> <c> } }"));
        assert!(!is_graph_safe(
            "WITH <g> DELETE { ?s ?p ?o } WHERE { ?s ?p ?o }"
        ));
        assert!(!is_graph_safe("insert data { graph <g> { <a> <b> <c> } }"));
    }
}
