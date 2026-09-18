//! The server-agent index — the cross-user query surface (ADR 0005).
//!
//! **Pointers and filter keys only, never content** (D5). A row carries the
//! note's IRI plus exactly what a timeline query filters and sorts on; the
//! content is dereferenced from the author's pod, and only for the rows that
//! survive pagination. That collapses store opens from O(local users) to
//! O(page size).
//!
//! Two consequences follow from holding pointers rather than copies:
//!
//! * **Dangling rows are the correct steady state.** Deleting a user is
//!   `rm -rf` on one directory; rows pointing into it sweep lazily on
//!   dereference. An index that a delete had to remember to update would have
//!   become a source of truth.
//! * **It is rebuildable.** [`clear`] plus a replay of pod contents reproduces
//!   it, which is what keeps it honest.
//!
//! Populated by **push**, not by crawling: the server agent is a delivery
//! recipient like any other and its processor writes the row. Rebuilding is the
//! repair path, not the normal one.

use oxigraph::model::Variable;
use oxigraph::model::{GraphName, GraphNameRef, Literal, NamedNode, NamedOrBlankNode, Quad, Term};
use oxigraph::sparql::{QueryResults, SparqlEvaluator};
use oxigraph::store::Store;

use crate::manager::StoreError;
use crate::write::{WriteError, insert_quads};

/// Graph holding the public/local timeline index (ADR 0005 R1).
pub const PUBLIC_TIMELINE: &str = "https://brolly.id/index/public";

pub const P_AUTHOR: &str = "https://brolly.id/ns#author";
pub const P_PUBLISHED: &str = "https://brolly.id/ns#published";
pub const P_AUDIENCE: &str = "https://brolly.id/ns#audience";
pub const P_IN_REPLY_TO: &str = "https://brolly.id/ns#inReplyTo";

/// Every predicate the index is permitted to use.
///
/// `tests/storage_invariants.rs` asserts the stored graph uses nothing else,
/// so "pointers and filter keys only" is a build failure rather than a
/// convention. The ActivityPub processor is checked separately, since it is the
/// only thing that writes here.
pub const ALLOWED_PREDICATES: &[&str] = &[P_AUTHOR, P_PUBLISHED, P_AUDIENCE, P_IN_REPLY_TO];

/// One timeline row. Note the absence of any content field — that is the point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotePointer {
    /// Dereferenceable IRI in the author's pod. Also names the owner, which is
    /// why status lookup needs no separate routing table.
    pub note: NamedNode,
    pub author: NamedNode,
    /// RFC 3339. Sorts lexicographically, which is why it is stored as a string.
    pub published: String,
    pub audience: NamedNode,
    pub in_reply_to: Option<NamedNode>,
}

fn iri(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

fn graph() -> GraphName {
    GraphName::NamedNode(iri(PUBLIC_TIMELINE))
}

/// Record a note in the public timeline index.
///
/// **The first record wins.** If the note is already indexed, nothing is
/// written. A pointer names one author and one published time. A second author
/// triple would let anyone who boosts a post claim it, and `count_notes` would
/// count it twice. A second `published` literal would list the note twice in
/// [`public_timeline`], once at the later time.
pub fn record_note(store: &Store, pointer: &NotePointer) -> Result<(), WriteError> {
    // Check-then-write has to be atomic, or two first records of one note (a
    // redelivered Create racing its original) would both write. A process-wide
    // lock is enough: RocksDB lets only one process open the instance store.
    // A poisoned lock only means a writer panicked; the check below re-reads
    // the store, so there is no state to distrust.
    static RECORDING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _recording = RECORDING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    if is_indexed(store, &pointer.note)? {
        return Ok(());
    }

    let subject = NamedOrBlankNode::NamedNode(pointer.note.clone());
    let mut quads = vec![
        Quad::new(
            subject.clone(),
            iri(P_AUTHOR),
            Term::NamedNode(pointer.author.clone()),
            graph(),
        ),
        Quad::new(
            subject.clone(),
            iri(P_PUBLISHED),
            Term::Literal(Literal::new_simple_literal(&pointer.published)),
            graph(),
        ),
        Quad::new(
            subject.clone(),
            iri(P_AUDIENCE),
            Term::NamedNode(pointer.audience.clone()),
            graph(),
        ),
    ];
    if let Some(parent) = &pointer.in_reply_to {
        quads.push(Quad::new(
            subject,
            iri(P_IN_REPLY_TO),
            Term::NamedNode(parent.clone()),
            graph(),
        ));
    }
    insert_quads(store, &quads)?;
    Ok(())
}

/// Is this note on the public timeline?
///
/// A pointer always has exactly one author triple, so that is what's checked.
/// A read, not a write: the ActivityPub processor asks before it lets an
/// `Announce` touch the index.
pub fn is_indexed(store: &Store, note: &NamedNode) -> Result<bool, StoreError> {
    let subject = NamedOrBlankNode::NamedNode(note.clone());
    let first = store
        .quads_for_pattern(
            Some((&subject).into()),
            Some(iri(P_AUTHOR).as_ref()),
            None,
            Some(GraphNameRef::NamedNode(iri(PUBLIC_TIMELINE).as_ref())),
        )
        .next()
        .transpose()?;
    Ok(first.is_some())
}

/// Drop a row — used when a dereference 404s, i.e. the pod no longer has it.
pub fn forget_note(store: &Store, note: &NamedNode) -> Result<(), StoreError> {
    let subject = NamedOrBlankNode::NamedNode(note.clone());
    let stale: Vec<Quad> = store
        .quads_for_pattern(
            Some((&subject).into()),
            None,
            None,
            Some(GraphNameRef::NamedNode(iri(PUBLIC_TIMELINE).as_ref())),
        )
        .filter_map(Result::ok)
        .collect();
    for quad in &stale {
        store.remove(quad)?;
    }
    Ok(())
}

/// The AS2 public collection — the audience a public post is addressed to.
pub const PUBLIC_AUDIENCE: &str = "https://www.w3.org/ns/activitystreams#Public";

/// Note IRIs on the public timeline, newest first.
///
/// A convenience over [`public_timeline`] that takes and returns plain strings,
/// so a caller can page the public timeline without depending on oxigraph. The
/// engine stays an implementation detail of this crate, which is the same
/// reason `Store` is re-exported rather than imported everywhere.
pub fn public_note_iris(
    store: &Store,
    limit: usize,
    before: Option<&str>,
) -> Result<Vec<String>, StoreError> {
    Ok(
        public_timeline(store, &iri(PUBLIC_AUDIENCE), limit, before)?
            .into_iter()
            .map(|pointer| pointer.note.as_str().to_string())
            .collect(),
    )
}

/// How many notes the index knows about.
///
/// Counted here rather than by opening every pod — this is exactly the
/// cross-user question the server agent exists to answer (ADR 0005 R8), and it
/// is the only number NodeInfo publishes beyond the member count.
///
/// Counts rows, not triples: `P_AUTHOR` appears exactly once per note, where a
/// bare graph count would inflate by however many optional predicates each row
/// happened to carry.
pub fn count_notes(store: &Store) -> Result<i64, StoreError> {
    Ok(store
        .quads_for_pattern(
            None,
            Some(iri(P_AUTHOR).as_ref()),
            None,
            Some(GraphNameRef::NamedNode(iri(PUBLIC_TIMELINE).as_ref())),
        )
        .filter_map(Result::ok)
        .count() as i64)
}

/// Wipe the index. The first half of a rebuild.
pub fn clear(store: &Store) -> Result<(), StoreError> {
    store.clear_graph(GraphNameRef::NamedNode(iri(PUBLIC_TIMELINE).as_ref()))?;
    Ok(())
}

/// The public/local timeline, newest first.
///
/// A **SPARQL query**, not a pattern-scan loop (decision D3). Filtering and
/// ordering happen in the engine; the caller dereferences content only for the
/// page that survives — bounded by `limit`, not by instance size.
///
/// Values are bound with `substitute_variable` rather than interpolated into
/// the query text, so there is no escaping to get wrong and no injection
/// surface. The cursor is always present, defaulting to a timestamp later than
/// any real one, which keeps this a single prepared query instead of two.
///
/// Note the API constraint: **a substituted variable must appear in the SELECT
/// projection**, otherwise oxigraph rejects the substitution outright. That is
/// why `?audience` and `?cursor` are projected even though the caller never
/// reads those columns.
pub fn public_timeline(
    store: &Store,
    audience: &NamedNode,
    limit: usize,
    before: Option<&str>,
) -> Result<Vec<NotePointer>, StoreError> {
    const OPEN_CURSOR: &str = "9999-12-31T23:59:59Z";

    let query = format!(
        r#"
        SELECT ?note ?author ?published ?parent ?audience ?cursor WHERE {{
          GRAPH <{PUBLIC_TIMELINE}> {{
            ?note <{P_AUTHOR}>    ?author ;
                  <{P_PUBLISHED}> ?published ;
                  <{P_AUDIENCE}>  ?audience .
            OPTIONAL {{ ?note <{P_IN_REPLY_TO}> ?parent }}
            FILTER(STR(?published) < STR(?cursor))
          }}
        }}
        ORDER BY DESC(?published)
        LIMIT {limit}
        "#
    );

    let cursor = Literal::new_simple_literal(before.unwrap_or(OPEN_CURSOR));
    let results = SparqlEvaluator::new()
        .parse_query(&query)
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .substitute_variable(
            Variable::new("audience").map_err(|e| StoreError::Backend(e.to_string()))?,
            audience.clone(),
        )
        .substitute_variable(
            Variable::new("cursor").map_err(|e| StoreError::Backend(e.to_string()))?,
            cursor,
        )
        .on_store(store)
        .execute()
        .map_err(|e| StoreError::Backend(e.to_string()))?;

    let QueryResults::Solutions(solutions) = results else {
        return Err(StoreError::Backend("expected SELECT solutions".into()));
    };

    let mut out = Vec::new();
    for solution in solutions {
        let solution = solution.map_err(|e| StoreError::Backend(e.to_string()))?;
        let (Some(Term::NamedNode(note)), Some(Term::NamedNode(author))) =
            (solution.get("note"), solution.get("author"))
        else {
            continue;
        };
        let Some(Term::Literal(published)) = solution.get("published") else {
            continue;
        };
        out.push(NotePointer {
            note: note.clone(),
            author: author.clone(),
            published: published.value().to_string(),
            audience: audience.clone(),
            in_reply_to: match solution.get("parent") {
                Some(Term::NamedNode(p)) => Some(p.clone()),
                _ => None,
            },
        });
    }
    Ok(out)
}
