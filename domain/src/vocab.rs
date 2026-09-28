//! Canonical vocabulary terms.
//!
//! AS2 plus FOAF/vCard is the canonical layer (decision D7). Our own namespace
//! covers only what neither provides — the faithful-layer structural markers.

/// ActivityStreams 2.0. Canonical form is **https**; see [`crate::iri`] for why
/// that matters and what happens to the `http` variant.
pub const AS2: &str = "https://www.w3.org/ns/activitystreams#";
pub const FOAF: &str = "http://xmlns.com/foaf/0.1/";
pub const VCARD: &str = "http://www.w3.org/2006/vcard/ns#";
pub const RDF: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
pub const XSD: &str = "http://www.w3.org/2001/XMLSchema#";
pub const LDP: &str = "http://www.w3.org/ns/ldp#";
pub const ACL: &str = "http://www.w3.org/ns/auth/acl#";
pub const SECURITY: &str = "https://w3id.org/security#";
pub const MASTODON: &str = "http://joinmastodon.org/ns#";
/// Solid's own terms. `oidcIssuer` lives here, and it is the triple that makes
/// WebID-first login possible: an app handed a WebID dereferences it and reads
/// this to learn where to authenticate. Without it there is nothing to log in
/// to, however well the OIDC endpoints themselves work.
pub const SOLID: &str = "http://www.w3.org/ns/solid/terms#";
/// The personal-data-space vocabulary. `space:storage` is how a client
/// discovers the pod root rather than guessing at it.
pub const SPACE: &str = "http://www.w3.org/ns/pim/space#";

/// Ours. Structural markers for the faithful layer, and anything the standard
/// vocabularies genuinely lack.
pub const BROLLY: &str = "https://brolly.id/ns#";

/// Marks a node that stands for a JSON object, so an empty object survives a
/// round trip instead of vanishing into a subject with no triples.
pub const JSON_OBJECT: &str = "https://brolly.id/ns#JsonObject";
/// Stands for JSON `null`, which has no RDF literal equivalent.
pub const JSON_NULL: &str = "https://brolly.id/ns#null";
/// Records the lexicon a faithful-layer record came from.
pub const LEXICON: &str = "https://brolly.id/ns#lexicon";

pub const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
pub const RDF_FIRST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#first";
pub const RDF_REST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest";
pub const RDF_NIL: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil";

pub const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
pub const XSD_INTEGER: &str = "http://www.w3.org/2001/XMLSchema#integer";
pub const XSD_DOUBLE: &str = "http://www.w3.org/2001/XMLSchema#double";
pub const XSD_BOOLEAN: &str = "http://www.w3.org/2001/XMLSchema#boolean";

/// Whether follows need approval. AS2's own term, and the one Mastodon reads
/// to render a lock on a profile — so it federates without translation.
pub const AS2_MANUALLY_APPROVES: &str =
    "https://www.w3.org/ns/activitystreams#manuallyApprovesFollowers";

/// Mastodon's own extensions, in their namespace rather than ours. Inventing
/// private terms for things the ecosystem already names is how a profile stops
/// round-tripping.
pub const MASTODON_DISCOVERABLE: &str = "http://joinmastodon.org/ns#discoverable";
pub const MASTODON_BOT: &str = "http://joinmastodon.org/ns#bot";

// --- canonical-layer predicates we actually map onto -----------------------
pub const FOAF_NAME: &str = "http://xmlns.com/foaf/0.1/name";
pub const FOAF_DEPICTION: &str = "http://xmlns.com/foaf/0.1/depiction";
pub const VCARD_NOTE: &str = "http://www.w3.org/2006/vcard/ns#note";

pub const FOAF_PERSON: &str = "http://xmlns.com/foaf/0.1/Person";
/// The *document* is not the person. `foaf:primaryTopic` is the link between
/// them, and keeping them distinct is why the WebID carries a `#me` fragment.
pub const FOAF_PERSONAL_PROFILE_DOCUMENT: &str =
    "http://xmlns.com/foaf/0.1/PersonalProfileDocument";
pub const FOAF_PRIMARY_TOPIC: &str = "http://xmlns.com/foaf/0.1/primaryTopic";
pub const SOLID_OIDC_ISSUER: &str = "http://www.w3.org/ns/solid/terms#oidcIssuer";
pub const SPACE_STORAGE: &str = "http://www.w3.org/ns/pim/space#storage";

// --- LDP resources and server-managed metadata (stage 5a) -------------------
//
// `store::resources` writes these into each pod's metadata graph, which it
// names and owns. They describe resources the server manages, so no client
// write can reach them there.

/// `r` exists. In the metadata graph this triple *is* existence.
pub const LDP_RESOURCE: &str = "http://www.w3.org/ns/ldp#Resource";
pub const LDP_CONTAINER: &str = "http://www.w3.org/ns/ldp#Container";
pub const LDP_BASIC_CONTAINER: &str = "http://www.w3.org/ns/ldp#BasicContainer";
pub const LDP_RDF_SOURCE: &str = "http://www.w3.org/ns/ldp#RDFSource";
pub const LDP_NON_RDF_SOURCE: &str = "http://www.w3.org/ns/ldp#NonRDFSource";
pub const LDP_CONTAINS: &str = "http://www.w3.org/ns/ldp#contains";
/// The class of a storage root. The same namespace as [`SPACE`]; Solid calls
/// it `pim:`.
pub const PIM_STORAGE: &str = "http://www.w3.org/ns/pim/space#Storage";

pub const DCTERMS: &str = "http://purl.org/dc/terms/";
pub const DCTERMS_MODIFIED: &str = "http://purl.org/dc/terms/modified";
pub const XSD_DATE_TIME: &str = "http://www.w3.org/2001/XMLSchema#dateTime";

/// An auxiliary resource (today only an `.acl`). Recorded, never contained.
pub const BROLLY_AUXILIARY: &str = "https://brolly.id/ns#Auxiliary";
/// A resource's version: a new ULID on every change, served as its `ETag`.
pub const BROLLY_VERSION: &str = "https://brolly.id/ns#version";
/// The pod's metadata layout version.
pub const BROLLY_LAYOUT: &str = "https://brolly.id/ns#layout";
/// Binary metadata (ADR 0013). No standard vocabulary names a
/// content-addressed blob; the digest is the join to the blob store.
pub const BROLLY_BLOB_DIGEST: &str = "https://brolly.id/ns#blobDigest";
pub const BROLLY_MEDIA_TYPE: &str = "https://brolly.id/ns#mediaType";
pub const BROLLY_BYTE_SIZE: &str = "https://brolly.id/ns#byteSize";

// --- discovery (stage 5b, H6 and H8) ---------------------------------------
//
// The link relations a pod read advertises. The LDP classes above are the
// `rel="type"` *values*; these two are relation IRIs, which is what `rel=`
// carries when no short name is registered.

/// `Link rel="…#owner"` on the storage root, and the predicate the storage
/// description uses for the same statement. Solid Protocol §4.1.
pub const SOLID_OWNER: &str = "http://www.w3.org/ns/solid/terms#owner";
/// `Link rel="…#storageDescription"` on every resource in a storage
/// (Solid Protocol §4.1). Points at the generated document
/// `brolly_solid::storage_description` serves.
pub const SOLID_STORAGE_DESCRIPTION: &str = "http://www.w3.org/ns/solid/terms#storageDescription";

#[cfg(test)]
mod tests {
    use super::*;

    /// These two IRIs are what a `Link` header's `rel=` carries **verbatim**
    /// — Solid has no registered short name for either — so a typo is a link
    /// relation no client recognises, not a compile error.
    #[test]
    fn the_discovery_relations_are_solid_terms() {
        for term in [SOLID_OWNER, SOLID_STORAGE_DESCRIPTION] {
            assert!(term.starts_with(SOLID), "{term}");
        }
        assert_eq!(SOLID_OWNER, "http://www.w3.org/ns/solid/terms#owner");
        assert_eq!(
            SOLID_STORAGE_DESCRIPTION,
            "http://www.w3.org/ns/solid/terms#storageDescription"
        );
    }

    #[test]
    fn resource_terms_live_in_their_namespaces() {
        for term in [
            LDP_RESOURCE,
            LDP_CONTAINER,
            LDP_BASIC_CONTAINER,
            LDP_RDF_SOURCE,
            LDP_NON_RDF_SOURCE,
            LDP_CONTAINS,
        ] {
            assert!(term.starts_with(LDP), "{term}");
        }
        assert!(PIM_STORAGE.starts_with(SPACE));
        assert!(DCTERMS_MODIFIED.starts_with(DCTERMS));
        assert!(XSD_DATE_TIME.starts_with(XSD));
        for term in [
            BROLLY_AUXILIARY,
            BROLLY_VERSION,
            BROLLY_LAYOUT,
            BROLLY_BLOB_DIGEST,
            BROLLY_MEDIA_TYPE,
            BROLLY_BYTE_SIZE,
        ] {
            assert!(term.starts_with(BROLLY), "{term}");
        }
    }

    #[test]
    fn the_blob_terms_keep_the_iris_already_stored() {
        // ADR 0013 pods already hold triples with these IRIs; the upgrade reads
        // them back, so moving the constants must not rename them.
        assert_eq!(BROLLY_BLOB_DIGEST, "https://brolly.id/ns#blobDigest");
        assert_eq!(BROLLY_MEDIA_TYPE, "https://brolly.id/ns#mediaType");
        assert_eq!(BROLLY_BYTE_SIZE, "https://brolly.id/ns#byteSize");
    }
}
