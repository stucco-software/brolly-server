//! WAC evaluation.

use brolly_domain::vocab;
use brolly_store::PodRead;
use brolly_store::resources::METADATA_GRAPH;
use oxigraph::model::{NamedNode, Term};
use oxigraph::sparql::QueryResults;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzError {
    Query(String),
}

impl std::fmt::Display for AuthzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthzError::Query(e) => write!(f, "authz query: {e}"),
        }
    }
}

impl std::error::Error for AuthzError {}

/// Who is asking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Agent {
    /// No credential presented. Only `acl:agentClass foaf:Agent` can grant.
    Anonymous,
    /// A verified WebID.
    Authenticated(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    Read,
    Write,
    Append,
    Control,
}

impl AccessMode {
    fn iri(self) -> &'static str {
        match self {
            AccessMode::Read => "http://www.w3.org/ns/auth/acl#Read",
            AccessMode::Write => "http://www.w3.org/ns/auth/acl#Write",
            AccessMode::Append => "http://www.w3.org/ns/auth/acl#Append",
            AccessMode::Control => "http://www.w3.org/ns/auth/acl#Control",
        }
    }

    /// Modes that satisfy this request. `acl:Write` implies `acl:Append`, so an
    /// Append request is also satisfied by a Write grant.
    fn satisfying(self) -> Vec<&'static str> {
        match self {
            AccessMode::Append => vec![AccessMode::Append.iri(), AccessMode::Write.iri()],
            other => vec![other.iri()],
        }
    }
}

/// Which ACL applies to a resource, and whether it was found on the resource
/// itself or inherited from an ancestor container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveAcl {
    pub graph: NamedNode,
    /// `true` when the ACL is the resource's own, so authorizations match via
    /// `acl:accessTo`. `false` when inherited, matching `acl:default`.
    pub direct: bool,
    /// The IRI that authorizations inside this ACL actually refer to.
    ///
    /// This is **not** always the requested resource. A direct ACL scopes to the
    /// resource, but an inherited one scopes to the *container* that owns it —
    /// `/notes/.acl` says `acl:default </notes/>`, never `acl:default
    /// </notes/first>`. Deriving it here rather than in [`authorize`] removes
    /// the chance of matching against the wrong subject, which is a silent
    /// over- or under-grant either way.
    ///
    /// Conveniently it is the same derivation in both cases: the candidate IRI
    /// minus its `.acl` suffix.
    pub scope: NamedNode,
}

/// Candidate ACL graph IRIs for `path`, most specific first.
///
/// Pure string work: `/a/b/c` yields `/a/b/c.acl`, `/a/b/.acl`, `/a/.acl`,
/// `/.acl`. The hierarchy is in the IRI, so this needs no store access.
fn acl_candidates(base: &str, path: &str) -> Vec<String> {
    let path = path.trim_start_matches('/');
    let mut out = vec![format!("{base}/{path}.acl")];

    let mut segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    // The resource's own ACL is already pushed; ancestors are containers.
    segments.pop();
    loop {
        let prefix = segments.join("/");
        if prefix.is_empty() {
            out.push(format!("{base}/.acl"));
            break;
        }
        out.push(format!("{base}/{prefix}/.acl"));
        segments.pop();
    }
    out
}

/// Find the ACL that governs `path`.
///
/// **One query, not one probe per level.** Candidates are generated in Rust,
/// then a single `SELECT` asks which of them exist; the caller takes the most
/// specific. The predecessor issued a `resource_exists` round trip per
/// hierarchy level.
///
/// **An ACL exists when the pod's metadata records it** (spec 5a, R16), not
/// when its graph has triples. So an emptied ACL governs, and grants nothing,
/// instead of falling through to an ancestor's broader `acl:default`. Which
/// authorizations it holds is still read from its graph, by [`authorize`].
pub fn effective_acl(
    store: &impl PodRead,
    base: &str,
    path: &str,
) -> Result<Option<EffectiveAcl>, AuthzError> {
    let candidates = acl_candidates(base, path);
    let values = candidates
        .iter()
        .map(|c| format!("<{c}>"))
        .collect::<Vec<_>>()
        .join(" ");

    // Candidates are server-generated from a validated path, never user text.
    let query = format!(
        r#"
        SELECT DISTINCT ?acl WHERE {{
          VALUES ?acl {{ {values} }}
          GRAPH <{METADATA_GRAPH}> {{ ?acl a <{auxiliary}> }}
        }}
        "#,
        auxiliary = vocab::BROLLY_AUXILIARY,
    );

    let existing = select_iris(store, &query, "acl", &[])?;

    // `candidates` is ordered most-specific first, so the first hit wins.
    Ok(candidates.iter().enumerate().find_map(|(i, candidate)| {
        existing
            .iter()
            .any(|e| e == candidate)
            .then(|| EffectiveAcl {
                graph: NamedNode::new_unchecked(candidate),
                direct: i == 0,
                scope: NamedNode::new_unchecked(
                    candidate.strip_suffix(".acl").unwrap_or(candidate),
                ),
            })
    }))
}

/// Is `agent` granted `mode` by `acl`?
///
/// The subject matched against `acl:accessTo` / `acl:default` comes from
/// [`EffectiveAcl::scope`], not from the requested resource — see that field.
///
/// One query per decision. The four WAC agent-matching rules are a `UNION`, and
/// `acl:agentGroup` membership is a join into whichever graph holds the group —
/// the predecessor derived the group's graph by stripping the IRI fragment,
/// which only worked when the group document was named the way it expected.
pub fn authorize(
    store: &impl PodRead,
    acl: &EffectiveAcl,
    agent: &Agent,
    mode: AccessMode,
) -> Result<bool, AuthzError> {
    let scope = if acl.direct {
        "http://www.w3.org/ns/auth/acl#accessTo"
    } else {
        "http://www.w3.org/ns/auth/acl#default"
    };
    let modes = mode
        .satisfying()
        .iter()
        .map(|m| format!("<{m}>"))
        .collect::<Vec<_>>()
        .join(" ");

    let acl_iri = acl.graph.as_str();
    let foaf_agent = format!("{}Agent", vocab::FOAF);
    let acl_ns = vocab::ACL;
    let vcard_member = format!("{}hasMember", vocab::VCARD);

    // Anonymous callers get only the public branch; including the agent-specific
    // branches would require binding a WebID that does not exist.
    let agent_branches = match agent {
        Agent::Anonymous => String::new(),
        Agent::Authenticated(_) => format!(
            r#"
            UNION {{ ?auth <{acl_ns}agentClass> <{acl_ns}AuthenticatedAgent> }}
            UNION {{ ?auth <{acl_ns}agent> ?agent }}
            UNION {{
              ?auth <{acl_ns}agentGroup> ?group .
              GRAPH ?groupDoc {{ ?group <{vcard_member}> ?agent }}
            }}
            "#
        ),
    };

    // `?agent` and `?target` are projected because oxigraph requires a
    // substituted variable to appear in the SELECT projection.
    let query = format!(
        r#"
        SELECT ?agent ?target WHERE {{
          VALUES ?mode {{ {modes} }}
          GRAPH <{acl_iri}> {{
            ?auth <{scope}> ?target ;
                  <{acl_ns}mode> ?mode .
            {{ ?auth <{acl_ns}agentClass> <{foaf_agent}> }}
            {agent_branches}
          }}
        }}
        LIMIT 1
        "#
    );

    let mut bindings: Vec<(&str, Term)> = vec![("target", Term::NamedNode(acl.scope.clone()))];
    if let Agent::Authenticated(webid) = agent {
        bindings.push(("agent", Term::NamedNode(NamedNode::new_unchecked(webid))));
    }

    let rows = select_iris(store, &query, "target", &bindings)?;
    Ok(!rows.is_empty())
}

/// Run a SELECT with substituted IRI bindings, returning one projected column.
///
/// The bindings go through `PodRead::query_with`, which substitutes them into
/// the prepared query, so no IRI is ever written into the query text.
fn select_iris(
    store: &impl PodRead,
    query: &str,
    column: &str,
    bindings: &[(&str, Term)],
) -> Result<Vec<String>, AuthzError> {
    let results = store
        .query_with(query, bindings)
        .map_err(|e| AuthzError::Query(e.to_string()))?;

    let QueryResults::Solutions(solutions) = results else {
        return Err(AuthzError::Query("expected SELECT solutions".into()));
    };

    let mut out = Vec::new();
    for solution in solutions {
        let solution = solution.map_err(|e| AuthzError::Query(e.to_string()))?;
        match solution.get(column) {
            Some(oxigraph::model::Term::NamedNode(n)) => out.push(n.as_str().to_string()),
            _ => out.push(String::new()),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_run_most_specific_first() {
        let c = acl_candidates("https://alice.brolly.id", "/notes/2026/post");
        assert_eq!(
            c,
            vec![
                "https://alice.brolly.id/notes/2026/post.acl",
                "https://alice.brolly.id/notes/2026/.acl",
                "https://alice.brolly.id/notes/.acl",
                "https://alice.brolly.id/.acl",
            ]
        );
    }

    #[test]
    fn root_resource_falls_back_to_the_root_acl() {
        let c = acl_candidates("https://alice.brolly.id", "/profile");
        assert_eq!(
            c,
            vec![
                "https://alice.brolly.id/profile.acl",
                "https://alice.brolly.id/.acl",
            ]
        );
    }

    #[test]
    fn write_satisfies_append_but_not_the_reverse() {
        assert!(
            AccessMode::Append
                .satisfying()
                .contains(&AccessMode::Write.iri())
        );
        assert!(
            !AccessMode::Write
                .satisfying()
                .contains(&AccessMode::Append.iri())
        );
    }
}
