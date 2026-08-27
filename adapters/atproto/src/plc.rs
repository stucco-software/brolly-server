//! `did:plc` — creating the identity, not just resolving it.
//!
//! atrium resolves a `did:plc` (`atrium-identity`'s PLC resolver); creating one
//! is a PDS's job, so it lives here.
//!
//! **The DID is derived from the operation, not assigned.** It is the first 24
//! characters of base32(sha256(dag-cbor(signed genesis operation))), which
//! means the identifier commits to the keys and the handle it was created
//! with. Nobody hands it out and nobody can pick it, which is the property that
//! makes `did:plc` portable: a member can take it to another PDS because it was
//! never ours to begin with.
//!
//! D11 wants this in every wire format from the first commit, so there is no
//! AT-URI migration later. `did:web` stays routing-only.

use base32::Alphabet;
use brolly_identity::db::DbError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::keys::SigningKey;

/// How much of the hash the DID carries. Fixed by the specification.
const DID_LENGTH: usize = 24;

/// A PLC genesis operation, in the field order the spec defines.
///
/// Serialization order matters: the DID is a hash of the DAG-CBOR encoding, so
/// a reordering changes the identifier. DAG-CBOR sorts map keys canonically,
/// which is what makes that hash reproducible across implementations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Operation {
    #[serde(rename = "type")]
    pub op_type: String,
    /// Keys permitted to sign the *next* operation. Rotation is what recovery
    /// from a compromised signing key depends on, so there is more than one.
    #[serde(rename = "rotationKeys")]
    pub rotation_keys: Vec<String>,
    /// `atproto` → the repo signing key, as `did:key`.
    #[serde(rename = "verificationMethods")]
    pub verification_methods: std::collections::BTreeMap<String, String>,
    /// The handle, as `at://handle`. A handle is rented; the DID is not, which
    /// is why this points one way and never the other.
    #[serde(rename = "alsoKnownAs")]
    pub also_known_as: Vec<String>,
    pub services: std::collections::BTreeMap<String, Service>,
    /// `None` for a genesis operation; the previous operation's CID after that.
    pub prev: Option<String>,
    /// Absent while signing, present afterwards.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Service {
    #[serde(rename = "type")]
    pub service_type: String,
    pub endpoint: String,
}

#[derive(Debug)]
pub enum PlcError {
    Encode(String),
    Signing(String),
}

impl std::fmt::Display for PlcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlcError::Encode(e) => write!(f, "encoding a PLC operation: {e}"),
            PlcError::Signing(e) => write!(f, "signing a PLC operation: {e}"),
        }
    }
}

impl std::error::Error for PlcError {}

impl From<DbError> for PlcError {
    fn from(e: DbError) -> Self {
        PlcError::Signing(e.to_string())
    }
}

/// Build an unsigned genesis operation.
pub fn genesis(
    signing_key: &SigningKey,
    rotation_keys: &[String],
    handle: &str,
    pds_endpoint: &str,
) -> Operation {
    Operation {
        op_type: "plc_operation".into(),
        rotation_keys: rotation_keys.to_vec(),
        verification_methods: [("atproto".to_string(), signing_key.did_key())]
            .into_iter()
            .collect(),
        also_known_as: vec![format!("at://{handle}")],
        services: [(
            "atproto_pds".to_string(),
            Service {
                service_type: "AtprotoPersonalDataServer".into(),
                endpoint: pds_endpoint.to_string(),
            },
        )]
        .into_iter()
        .collect(),
        prev: None,
        sig: None,
    }
}

/// The bytes an operation is signed over: its DAG-CBOR **without** `sig`.
pub fn signing_payload(operation: &Operation) -> Result<Vec<u8>, PlcError> {
    let unsigned = Operation {
        sig: None,
        ..operation.clone()
    };
    serde_ipld_dagcbor::to_vec(&unsigned).map_err(|e| PlcError::Encode(e.to_string()))
}

/// Sign an operation with a rotation key.
///
/// Signed by a **rotation** key, not the repo signing key. They are usually
/// different keys with different lifetimes: the repo key signs commits
/// constantly and is the one likelier to leak, and recovery means rotating it
/// using a key that was never in that path.
pub fn sign(operation: &Operation, rotation_key: &SigningKey) -> Result<Operation, PlcError> {
    let payload = signing_payload(operation)?;
    let signature = rotation_key.sign(&payload)?;

    Ok(Operation {
        sig: Some(base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            signature,
        )),
        ..operation.clone()
    })
}

/// Derive the DID a signed genesis operation produces.
///
/// `did:plc:` plus the first 24 characters of base32-lowercase over
/// SHA-256 of the operation's DAG-CBOR. Deriving rather than assigning is what
/// makes the identifier portable — it commits to the keys it was created with
/// and belongs to nobody.
pub fn did_for(signed: &Operation) -> Result<String, PlcError> {
    let bytes = serde_ipld_dagcbor::to_vec(signed).map_err(|e| PlcError::Encode(e.to_string()))?;
    let hash = Sha256::digest(&bytes);
    let encoded = base32::encode(Alphabet::Rfc4648Lower { padding: false }, &hash);
    Ok(format!("did:plc:{}", &encoded[..DID_LENGTH]))
}

/// Create a signed genesis operation and the DID it yields.
pub fn create(
    signing_key: &SigningKey,
    rotation_key: &SigningKey,
    handle: &str,
    pds_endpoint: &str,
) -> Result<(Operation, String), PlcError> {
    let operation = genesis(signing_key, &[rotation_key.did_key()], handle, pds_endpoint);
    let signed = sign(&operation, rotation_key)?;
    let did = did_for(&signed)?;
    Ok((signed, did))
}

/// The PLC directory entry for a DID.
///
/// Submission is **not** gated by the federation switch (ADR 0016). That switch
/// governs ActivityPub's outbound *delivery*, where suppressing it costs a
/// member nothing local. ATProtocol has no equivalent: a member without a
/// registered `did:plc` has no ATProtocol identity at all — not a degraded one,
/// none — and cannot later take elsewhere the DID that was never created.
pub fn directory_url(did: &str) -> String {
    format!("https://plc.directory/{did}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const HANDLE: &str = "alice.brolly.test";
    const PDS: &str = "https://brolly.test";

    #[test]
    fn a_did_is_derived_from_the_operation_that_created_it() {
        let signing = SigningKey::generate();
        let rotation = SigningKey::generate();

        let (signed, did) = create(&signing, &rotation, HANDLE, PDS).expect("create");

        assert!(did.starts_with("did:plc:"), "got {did}");
        assert_eq!(
            did.len(),
            "did:plc:".len() + DID_LENGTH,
            "a did:plc is a fixed width the whole network assumes"
        );
        // Derivation is a function of the operation, so it reproduces.
        assert_eq!(did_for(&signed).unwrap(), did);
    }

    #[test]
    fn a_did_uses_only_the_base32_alphabet() {
        // Uppercase or padding here and resolvers reject it.
        let (_, did) = create(
            &SigningKey::generate(),
            &SigningKey::generate(),
            HANDLE,
            PDS,
        )
        .unwrap();
        let suffix = did.strip_prefix("did:plc:").unwrap();
        assert!(
            suffix
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "unexpected characters in {suffix}"
        );
        assert!(!suffix.contains('='), "base32 padding leaked into the DID");
    }

    #[test]
    fn different_keys_produce_different_dids() {
        // The identifier commits to the keys it was created with; two members
        // sharing one would be catastrophic and silent.
        let (_, first) = create(
            &SigningKey::generate(),
            &SigningKey::generate(),
            HANDLE,
            PDS,
        )
        .unwrap();
        let (_, second) = create(
            &SigningKey::generate(),
            &SigningKey::generate(),
            HANDLE,
            PDS,
        )
        .unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn the_signature_covers_the_operation_but_not_itself() {
        // Signing over a payload containing the signature is not possible; the
        // payload has to exclude `sig`, and a verifier reconstructs it the same
        // way.
        let rotation = SigningKey::generate();
        let operation = genesis(&SigningKey::generate(), &[rotation.did_key()], HANDLE, PDS);
        let signed = sign(&operation, &rotation).expect("sign");

        assert!(signed.sig.is_some());
        assert_eq!(
            signing_payload(&signed).unwrap(),
            signing_payload(&operation).unwrap(),
            "the payload must not change once the signature is attached"
        );
    }

    #[test]
    fn the_signature_verifies_against_the_rotation_key() {
        let rotation = SigningKey::generate();
        let operation = genesis(&SigningKey::generate(), &[rotation.did_key()], HANDLE, PDS);
        let signed = sign(&operation, &rotation).unwrap();

        let payload = signing_payload(&signed).unwrap();
        let signature = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            signed.sig.as_ref().unwrap(),
        )
        .expect("decode signature");

        assert!(
            atrium_crypto::verify::verify_signature(&rotation.did_key(), &payload, &signature)
                .is_ok()
        );
    }

    #[test]
    fn the_repo_key_is_published_as_the_atproto_verification_method() {
        // This is what a consumer resolves to check a commit signature. Getting
        // it wrong means every commit we publish fails verification.
        let signing = SigningKey::generate();
        let (signed, _) = create(&signing, &SigningKey::generate(), HANDLE, PDS).unwrap();

        assert_eq!(
            signed.verification_methods.get("atproto"),
            Some(&signing.did_key())
        );
    }

    #[test]
    fn the_rotation_key_is_not_the_repo_key() {
        // Recovery from a leaked repo key depends on a key that was never in
        // the commit-signing path.
        let signing = SigningKey::generate();
        let rotation = SigningKey::generate();
        let (signed, _) = create(&signing, &rotation, HANDLE, PDS).unwrap();

        assert_eq!(signed.rotation_keys, vec![rotation.did_key()]);
        assert_ne!(signed.rotation_keys[0], signing.did_key());
    }

    #[test]
    fn the_handle_is_recorded_as_an_alias_not_an_identity() {
        let (signed, _) = create(
            &SigningKey::generate(),
            &SigningKey::generate(),
            HANDLE,
            PDS,
        )
        .unwrap();
        assert_eq!(signed.also_known_as, vec![format!("at://{HANDLE}")]);
    }

    #[test]
    fn the_pds_endpoint_is_published_so_consumers_can_find_the_repo() {
        let (signed, _) = create(
            &SigningKey::generate(),
            &SigningKey::generate(),
            HANDLE,
            PDS,
        )
        .unwrap();
        let service = signed.services.get("atproto_pds").expect("a PDS service");
        assert_eq!(service.service_type, "AtprotoPersonalDataServer");
        assert_eq!(service.endpoint, PDS);
    }

    #[test]
    fn a_genesis_operation_has_no_predecessor() {
        let (signed, _) = create(
            &SigningKey::generate(),
            &SigningKey::generate(),
            HANDLE,
            PDS,
        )
        .unwrap();
        assert_eq!(signed.prev, None, "a genesis operation follows nothing");
    }

    #[test]
    fn the_operation_round_trips_through_dag_cbor() {
        // The DID is a hash of this encoding, so anything that does not
        // round-trip would produce an identifier nobody else derives.
        let (signed, _) = create(
            &SigningKey::generate(),
            &SigningKey::generate(),
            HANDLE,
            PDS,
        )
        .unwrap();

        let bytes = serde_ipld_dagcbor::to_vec(&signed).unwrap();
        let decoded: Operation = serde_ipld_dagcbor::from_slice(&bytes).unwrap();
        assert_eq!(decoded, signed);
    }
}
