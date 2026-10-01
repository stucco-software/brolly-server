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

use brolly_authz::AccessMode;
use brolly_store::StoreError;
use brolly_store::resources::{PodRead, PodWrite};
use oxigraph::model::{GraphName, GraphNameRef, NamedNode, Quad};
use oxigraph::sparql::SparqlEvaluator;
use oxigraph::store::Store;
use oxttl::N3Parser;
use oxttl::n3::{N3Quad, N3Term};
use spargebra::GraphUpdateOperation;
use spargebra::SparqlParser;
use spargebra::term::{GraphName as SparqlGraphName, GraphNamePattern};

use crate::ldp::{self, LdpError, PatchBody};

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
    /// A SPARQL Update that is not one of the forms a PATCH may take: not an
    /// `INSERT`/`DELETE` form, or one that addresses a graph other than the
    /// resource's own — a `GRAPH` modifier, a `WITH` clause, a `LOAD`.
    EscapesGraph,
    /// The request's `If-Match` or `If-None-Match` didn't hold (412). Not
    /// `Precondition`, which is a `solid:where` that didn't bind (409).
    NotCurrent,
    Store(String),
    /// Refused by the LDP layer: WAC, the containment rule, a binary target,
    /// or the root.
    Ldp(LdpError),
}

impl std::fmt::Display for PatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatchError::Malformed(e) => write!(f, "malformed patch: {e}"),
            PatchError::NotAPatch(e) => write!(f, "not an InsertDeletePatch: {e}"),
            PatchError::Precondition(e) => write!(f, "precondition failed: {e}"),
            PatchError::EscapesGraph => write!(
                f,
                "SPARQL Update is not a form a PATCH may take — a PATCH may only \
                 INSERT or DELETE in the resource it addresses, and may not name \
                 a GRAPH, a WITH, a LOAD, a CLEAR, a DROP or a CREATE"
            ),
            PatchError::NotCurrent => {
                write!(f, "the resource is not at the version the request named")
            }
            PatchError::Store(e) => write!(f, "storage: {e}"),
            PatchError::Ldp(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PatchError {}

impl From<crate::conditional::PreconditionFailed> for PatchError {
    fn from(_: crate::conditional::PreconditionFailed) -> Self {
        PatchError::NotCurrent
    }
}

impl From<StoreError> for PatchError {
    fn from(e: StoreError) -> Self {
        PatchError::Ldp(LdpError::from(e))
    }
}

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

/// The update forms a PATCH may take (spec 5c, H7): an allow-list, because a
/// deny-list is how `LOAD` got missed — `LOAD` is "retrieve an IRI and insert
/// its contents", and `CLEAR`, `DROP`, `CREATE`, `ADD`, `MOVE` and `COPY` are
/// destructive or graph-addressing in ways the patch path does not model.
/// (`ADD`/`MOVE`/`COPY` arrive already rewritten by the parser into `Drop`s
/// and graph-named patterns, so they fall to both arms below.)
///
/// Every operation must be one of the three forms a patch speaks — `INSERT
/// DATA`, `DELETE DATA`, `DELETE/INSERT … WHERE` — and none may address a
/// graph other than the one it patches: a `GRAPH` modifier puts a named graph
/// on the quad, and a `WITH` clause arrives as a dataset over the default
/// graph with no `named` component. An explicit `USING` keeps `named` `Some`
/// and only narrows the `WHERE` — against a scratch store whose named graphs
/// are empty, so it matches nothing rather than escaping.
///
/// Both checks read the parsed update, never the bytes, which also retires
/// the substring matcher's false positives: a literal containing "with"
/// stops being refused as a graph escape.
fn is_patch_form(update: &spargebra::Update) -> bool {
    update.operations.iter().all(|op| match op {
        GraphUpdateOperation::InsertData { data } => data
            .iter()
            .all(|q| q.graph_name == SparqlGraphName::DefaultGraph),
        GraphUpdateOperation::DeleteData { data } => data
            .iter()
            .all(|q| q.graph_name == SparqlGraphName::DefaultGraph),
        GraphUpdateOperation::DeleteInsert {
            delete,
            insert,
            using,
            ..
        } => {
            using.as_ref().is_none_or(|ds| ds.named.is_some())
                && delete
                    .iter()
                    .all(|q| q.graph_name == GraphNamePattern::DefaultGraph)
                && insert
                    .iter()
                    .all(|q| q.graph_name == GraphNamePattern::DefaultGraph)
        }
        // `Load`, `Clear`, `Drop`, `Create` — and anything a future grammar
        // grows. A form the list never named is refused, not waved through.
        _ => false,
    })
}

/// Does this operation remove anything? (Spec 5c, H5: removal is
/// modification, so it is Write.) An empty `DELETE` clause deletes nothing,
/// wherever it appears — `INSERT { … } WHERE { … }` parses as a
/// `DeleteInsert` with an empty `delete`, and it adds.
fn deletes(op: &GraphUpdateOperation) -> bool {
    match op {
        GraphUpdateOperation::DeleteData { .. } => true,
        GraphUpdateOperation::DeleteInsert { delete, .. } => !delete.is_empty(),
        _ => false,
    }
}

/// A patch body, parsed once (spec 5c, H5 and H7): the classification
/// `ldp::patch_in` checks WAC against before anything is written, and the
/// update the solver runs after.
pub enum Prepared {
    /// An N3 Patch. Its `solid:where`/`solid:deletes` preconditions are
    /// checked against the scratch graph before the update runs — SPARQL
    /// silently succeeds where Solid requires failure.
    N3 {
        patch: N3Patch,
        update: spargebra::Update,
    },
    /// A SPARQL Update. No preconditions SPARQL cannot express.
    Sparql { update: spargebra::Update },
}

impl Prepared {
    /// The access mode this patch requires (spec 5c, H5): inserts only are
    /// **Append** — WAC's Append is "add … without the right to modify or
    /// remove" — and any delete is **Write**. A sequence of operations is as
    /// strong as its strongest.
    ///
    /// This reads the parse, never the bytes: a `DELETE` hidden inside a
    /// comment or a string literal that a bytes-level classifier misses is an
    /// Append-authorized destroy, and one imagined where none exists merely
    /// refuses an insert.
    pub fn mode(&self) -> AccessMode {
        match self {
            Prepared::N3 { patch, .. } if patch.deletes.is_empty() => AccessMode::Append,
            Prepared::N3 { .. } => AccessMode::Write,
            Prepared::Sparql { update } => {
                if update.operations.iter().any(deletes) {
                    AccessMode::Write
                } else {
                    AccessMode::Append
                }
            }
        }
    }

    /// Run the patch against `resource`'s graph and return the patched
    /// triples, without storing them.
    ///
    /// The profile document takes the solver and not the write-back: its graph
    /// is outside the storage root, so it stores as a bare graph through
    /// `PodWrite`'s outside-root family rather than as a recorded resource, and
    /// it filters the reserved positions out of the result first (spec 6, H1).
    /// Every other caller wants [`Prepared::apply`], which stores too.
    pub fn solve(self, w: &mut PodWrite<'_>, resource: &str) -> Result<Vec<Quad>, PatchError> {
        match self {
            Prepared::N3 { patch, update } => solve_scoped(w, resource, update, |scratch| {
                check_preconditions(scratch, &patch)
            }),
            Prepared::Sparql { update } => solve_scoped(w, resource, update, |_| Ok(())),
        }
    }

    /// Run the patch against `resource`, inside the caller's write.
    pub fn apply(self, w: &mut PodWrite<'_>, resource: &str) -> Result<(), PatchError> {
        let patched = self.solve(w, resource)?;
        ldp::store_patched(w, resource, patched).map_err(PatchError::Ldp)
    }
}

/// Parse a patch body — N3 Patch or SPARQL Update — into the form
/// [`Prepared`] applies, refusing everything the solver may not run (spec 5c,
/// H7). An N3 Patch's SPARQL translation is derived from parsed patterns, so
/// it is one of the allowed forms by construction; the check runs anyway, to
/// hold [`n3_patch_to_sparql`] to the same rule as a client's update.
pub fn prepare(body: PatchBody<'_>, resource: &str) -> Result<Prepared, PatchError> {
    match body {
        PatchBody::N3(bytes) => {
            let patch = parse_n3_patch(bytes, resource)?;
            let update = parse_update(&n3_patch_to_sparql(&patch), resource)?;
            if !is_patch_form(&update) {
                return Err(PatchError::EscapesGraph);
            }
            Ok(Prepared::N3 { patch, update })
        }
        PatchBody::SparqlUpdate(text) => {
            let update = parse_update(text, resource)?;
            if !is_patch_form(&update) {
                return Err(PatchError::EscapesGraph);
            }
            Ok(Prepared::Sparql { update })
        }
    }
}

/// Parse a SPARQL Update, resolving relative IRIs against the resource, as
/// the N3 path does. A syntax error is a malformed body (400), not a storage
/// failure (500).
fn parse_update(text: &str, base: &str) -> Result<spargebra::Update, PatchError> {
    SparqlParser::new()
        .with_base_iri(base)
        .map_err(|e| PatchError::Malformed(e.to_string()))?
        .parse_update(text)
        .map_err(|e| PatchError::Malformed(e.to_string()))
}

/// Run an update against one resource, in isolation, and return the result.
///
/// The resource's triples are copied into a scratch in-memory store as its
/// **default graph**, the update runs there verbatim, and the result comes
/// back as the resource's named graph for the caller to store — for a pod
/// resource, via [`ldp::store_patched`]; the profile stores it as a bare
/// outside-root graph instead (spec 6, H1).
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
///
/// A **container** target is seeded with everything a `GET` serves from
/// metadata as well (spec 5c, H6): the type triples, `ldp:contains`, and each
/// member's `dcterms:modified`/`stat:size` — the same one call `read_in`
/// makes, not a `contains`-only subset, because the rule is "match what a
/// listing shows" and a listing shows all of it. The write-back path is
/// unchanged: `store_patched` → `Content::Container` → `container_body`, so the
/// patch can *read* the members and still cannot rewrite them.
fn solve_scoped(
    w: &mut PodWrite<'_>,
    resource: &str,
    update: spargebra::Update,
    precondition: impl Fn(&Store) -> Result<(), PatchError>,
) -> Result<Vec<Quad>, PatchError> {
    let graph = NamedNode::new_unchecked(resource);

    let scratch = Store::new().map_err(|e| PatchError::Store(e.to_string()))?;
    let seed = |quad: oxigraph::model::Quad| -> Result<(), PatchError> {
        scratch
            .insert(&Quad::new(
                quad.subject,
                quad.predicate,
                quad.object,
                GraphName::DefaultGraph,
            ))
            .map_err(|e| PatchError::Store(e.to_string()))
    };
    for quad in w.quads_for_pattern(
        None,
        None,
        None,
        Some(GraphNameRef::NamedNode(graph.as_ref())),
    ) {
        seed(quad.map_err(|e| PatchError::Store(e.to_string()))?)?;
    }
    if crate::storage::is_container(resource) {
        for quad in brolly_store::resources::container_triples(w, resource)
            .map_err(|e| PatchError::Store(e.to_string()))?
        {
            seed(quad)?;
        }
    }

    precondition(&scratch)?;
    run_update(&scratch, update)?;

    Ok(scratch
        .quads_for_pattern(None, None, None, Some(GraphNameRef::DefaultGraph))
        .filter_map(Result::ok)
        .map(|q| Quad::new(q.subject, q.predicate, q.object, graph.clone()))
        .collect())
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

fn run_update(store: &Store, update: spargebra::Update) -> Result<(), PatchError> {
    SparqlEvaluator::new()
        .for_update(update)
        .on_store(store)
        .execute()
        .map_err(|e| PatchError::Store(e.to_string()))
}

/// Apply an N3 Patch to a resource, inside the caller's write, with no mode
/// check — the WAC-checked path is `ldp::patch_in`.
pub fn apply_n3_patch(w: &mut PodWrite<'_>, resource: &str, body: &[u8]) -> Result<(), PatchError> {
    prepare(PatchBody::N3(body), resource)?.apply(w, resource)
}

/// Apply a SPARQL Update to a resource, inside the caller's write, with no
/// mode check — the WAC-checked path is `ldp::patch_in`.
pub fn apply_sparql_update(
    w: &mut PodWrite<'_>,
    resource: &str,
    sparql: &str,
) -> Result<(), PatchError> {
    prepare(PatchBody::SparqlUpdate(sparql), resource)?.apply(w, resource)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// H7: the three forms pass, and everything else — a `GRAPH` modifier, a
    /// `WITH` clause, `LOAD`, `CLEAR`, `DROP`, `CREATE` — is refused, from the
    /// parse, so a literal containing "with" is not.
    #[test]
    fn only_patch_forms_pass() {
        let parse = |text: &str| {
            SparqlParser::new()
                .parse_update(text)
                .expect("the test's updates parse")
        };
        for ok in [
            "INSERT DATA { <a:b> <a:c> <a:d> }",
            "DELETE DATA { <a:b> <a:c> <a:d> }",
            "DELETE { ?s <a:c> <a:d> } WHERE { ?s <a:c> <a:d> }",
            // A USING keeps `named` `Some`: it narrows the WHERE against
            // empty named graphs rather than addressing one.
            "DELETE { ?s <a:c> <a:d> } USING <a:g> WHERE { ?s <a:c> <a:d> }",
            // A literal containing the keyword "with": the substring
            // matcher's false positive, retired.
            "INSERT DATA { <a:b> <a:c> \"with and graph\" }",
        ] {
            assert!(is_patch_form(&parse(ok)), "refused: {ok}");
        }
        for refused in [
            "INSERT DATA { GRAPH <a:g> { <a:b> <a:c> <a:d> } }",
            "WITH <a:g> DELETE { ?s ?p ?o } WHERE { ?s ?p ?o }",
            "LOAD <http://example.com/x>",
            "CLEAR DEFAULT",
            "DROP GRAPH <a:g>",
            "CREATE GRAPH <a:g>",
            "ADD DEFAULT TO <a:g>",
            "MOVE DEFAULT TO <a:g>",
            "COPY DEFAULT TO <a:g>",
            "DELETE WHERE { GRAPH <a:g> { ?s ?p ?o } }",
        ] {
            assert!(!is_patch_form(&parse(refused)), "accepted: {refused}");
        }
    }

    /// H5: classification reads the parse — inserts only are Append, any
    /// delete is Write, and a `DELETE` inside a string literal is not one.
    #[test]
    fn classification_reads_the_parse() {
        let parse = |text: &str| {
            SparqlParser::new()
                .parse_update(text)
                .expect("the test's updates parse")
        };
        let mode = |text: &str| {
            Prepared::Sparql {
                update: parse(text),
            }
            .mode()
        };
        assert_eq!(
            mode("INSERT DATA { <a:b> <a:c> <a:d> }"),
            AccessMode::Append
        );
        assert_eq!(mode("DELETE DATA { <a:b> <a:c> <a:d> }"), AccessMode::Write);
        assert_eq!(
            mode("DELETE { ?s <a:c> <a:d> } WHERE { ?s <a:c> <a:d> }"),
            AccessMode::Write
        );
        assert_eq!(
            mode("INSERT { ?s <a:c> <a:d> } WHERE { ?s <a:c> <a:d> }"),
            AccessMode::Append
        );
        assert_eq!(
            mode("INSERT DATA { <a:b> <a:c> \"DELETE everything\" }"),
            AccessMode::Append
        );
    }
}
