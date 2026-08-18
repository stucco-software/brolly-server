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

// --- canonical-layer predicates we actually map onto -----------------------
pub const FOAF_NAME: &str = "http://xmlns.com/foaf/0.1/name";
pub const FOAF_DEPICTION: &str = "http://xmlns.com/foaf/0.1/depiction";
pub const VCARD_NOTE: &str = "http://www.w3.org/2006/vcard/ns#note";
