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
