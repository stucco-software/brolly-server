//! Path helpers for the storage root.
//!
//! Existence, containment and the root itself live in the pod's metadata
//! (`brolly_store::resources`); this module only reads IRIs.

/// The container that directly holds `resource`.
///
/// `/~/a/b/c` → `/~/a/b/`, `/~/a/` → `/~/`. Returns `None` at the storage root,
/// which has no parent inside the pod.
pub fn parent_container(resource: &str, root: &str) -> Option<String> {
    if resource == root || !resource.starts_with(root) {
        return None;
    }
    let trimmed = resource.trim_end_matches('/');
    let cut = trimmed.rfind('/')?;
    let parent = &trimmed[..cut + 1];
    (parent.len() >= root.len()).then(|| parent.to_string())
}

/// True when the IRI names a container by LDP convention.
pub fn is_container(resource: &str) -> bool {
    resource.ends_with('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "https://alice.brolly.id/~/";

    #[test]
    fn parents_walk_up_to_the_storage_root() {
        assert_eq!(
            parent_container("https://alice.brolly.id/~/a/b/c", ROOT).as_deref(),
            Some("https://alice.brolly.id/~/a/b/")
        );
        assert_eq!(
            parent_container("https://alice.brolly.id/~/a/", ROOT).as_deref(),
            Some(ROOT)
        );
    }

    #[test]
    fn the_storage_root_has_no_parent() {
        assert_eq!(parent_container(ROOT, ROOT), None);
    }

    #[test]
    fn containment_never_escapes_the_pod() {
        // A path outside the root must not produce a parent, or containment
        // triples would be written onto protocol resources.
        assert_eq!(
            parent_container("https://alice.brolly.id/profile", ROOT),
            None
        );
        assert_eq!(
            parent_container("https://alice.brolly.id/oauth/token", ROOT),
            None
        );
    }

    #[test]
    fn containers_are_recognised_by_trailing_slash() {
        assert!(is_container("https://alice.brolly.id/~/notes/"));
        assert!(!is_container("https://alice.brolly.id/~/notes/first"));
    }
}
