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

/// The CID a PLC operation is referenced by in its successor's `prev`.
///
/// The DAG-CBOR of the *signed* operation, as a CIDv1 with the DAG-CBOR codec —
/// the same content addressing the repo uses, so an operation log is a chain
/// each link of which names its predecessor by content.
pub fn operation_cid(signed: &Operation) -> Result<String, PlcError> {
    use sha2::Digest;
    let bytes = serde_ipld_dagcbor::to_vec(signed).map_err(|e| PlcError::Encode(e.to_string()))?;
    let digest = Sha256::digest(&bytes);
    let mh =
        atrium_repo::Multihash::wrap(0x12, &digest).map_err(|e| PlcError::Encode(e.to_string()))?;
    Ok(atrium_repo::Cid::new_v1(0x71, mh).to_string())
}

/// Build an operation that rotates the repo signing key.
///
/// Rotation is the reason rotation keys are separate from the signing key at
/// all. The repo key signs every commit, so it is the one likeliest to leak;
/// recovery means replacing it using a key that was never in that path.
///
/// The new operation:
///
/// * names its predecessor in `prev`, so the log is a chain rather than a set
///   and a directory can reject an operation that forks it;
/// * is signed by a **current** rotation key, not by either signing key — the
///   compromised key must not be able to authorize its own replacement;
/// * keeps the DID unchanged, because the DID was derived from the *genesis*
///   operation and is deliberately not a function of the current keys. That is
///   what makes it survive rotation at all.
pub fn rotate_signing_key(
    previous: &Operation,
    previous_cid: &str,
    new_signing_key: &SigningKey,
    rotation_key: &SigningKey,
) -> Result<Operation, PlcError> {
    let mut next = Operation {
        prev: Some(previous_cid.to_string()),
        sig: None,
        ..previous.clone()
    };
    next.verification_methods
        .insert("atproto".to_string(), new_signing_key.did_key());

    sign(&next, rotation_key)
}

/// Build an operation that replaces the rotation keys themselves.
///
/// Signed by one of the *outgoing* keys, which is the only thing that could
/// authorize it — and the reason more than one rotation key is published: if
/// the only one is lost, nothing can ever sign again and the DID is frozen.
pub fn rotate_rotation_keys(
    previous: &Operation,
    previous_cid: &str,
    new_rotation_keys: &[String],
    signing_with: &SigningKey,
) -> Result<Operation, PlcError> {
    let next = Operation {
        prev: Some(previous_cid.to_string()),
        rotation_keys: new_rotation_keys.to_vec(),
        sig: None,
        ..previous.clone()
    };
    sign(&next, signing_with)
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

#[cfg(test)]
mod rotation_tests {
    use super::*;

    const HANDLE: &str = "alice.brolly.test";
    const PDS: &str = "https://brolly.test";

    fn a_genesis() -> (Operation, String, SigningKey, SigningKey) {
        let signing = SigningKey::generate();
        let rotation = SigningKey::generate();
        let (signed, did) = create(&signing, &rotation, HANDLE, PDS).expect("genesis");
        (signed, did, signing, rotation)
    }

    #[test]
    fn rotating_the_signing_key_keeps_the_did() {
        // The whole point of deriving the DID from the *genesis* operation: it
        // is not a function of the current keys, so it survives rotation. A DID
        // that changed when a key was replaced would make recovery
        // indistinguishable from starting over.
        let (genesis, did, _, rotation) = a_genesis();
        let cid = operation_cid(&genesis).expect("cid");
        let replacement = SigningKey::generate();

        let rotated = rotate_signing_key(&genesis, &cid, &replacement, &rotation).expect("rotate");

        assert_eq!(
            rotated.verification_methods.get("atproto"),
            Some(&replacement.did_key()),
            "the new key must be the published one"
        );
        // The DID is unchanged because it was never derived from this.
        assert_eq!(did_for(&genesis).unwrap(), did);
    }

    #[test]
    fn a_rotation_names_its_predecessor() {
        // So the log is a chain rather than a set, and a directory can reject
        // an operation that forks it.
        let (genesis, _, _, rotation) = a_genesis();
        let cid = operation_cid(&genesis).unwrap();

        let rotated =
            rotate_signing_key(&genesis, &cid, &SigningKey::generate(), &rotation).unwrap();

        assert_eq!(rotated.prev.as_deref(), Some(cid.as_str()));
        assert_ne!(rotated.prev, genesis.prev, "genesis follows nothing");
    }

    #[test]
    fn a_rotation_is_signed_by_the_rotation_key_not_the_signing_key() {
        // The compromised key must not be able to authorize its own
        // replacement — that would make rotation useless in the only scenario
        // it exists for.
        let (genesis, _, signing, rotation) = a_genesis();
        let cid = operation_cid(&genesis).unwrap();
        let rotated =
            rotate_signing_key(&genesis, &cid, &SigningKey::generate(), &rotation).unwrap();

        let payload = signing_payload(&rotated).unwrap();
        let signature = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            rotated.sig.as_ref().unwrap(),
        )
        .unwrap();

        assert!(
            atrium_crypto::verify::verify_signature(&rotation.did_key(), &payload, &signature)
                .is_ok(),
            "must verify against the rotation key"
        );
        assert!(
            atrium_crypto::verify::verify_signature(&signing.did_key(), &payload, &signature)
                .is_err(),
            "must not verify against the signing key it is replacing"
        );
    }

    #[test]
    fn a_compromised_signing_key_cannot_sign_its_own_rotation() {
        // Stated from the attacker's side: holding the leaked repo key gets
        // you an operation the directory will not accept, because it is not
        // signed by a rotation key.
        let (genesis, _, leaked, rotation) = a_genesis();
        let cid = operation_cid(&genesis).unwrap();

        let attempt = rotate_signing_key(&genesis, &cid, &SigningKey::generate(), &leaked).unwrap();
        let payload = signing_payload(&attempt).unwrap();
        let signature = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            attempt.sig.as_ref().unwrap(),
        )
        .unwrap();

        assert!(
            atrium_crypto::verify::verify_signature(&rotation.did_key(), &payload, &signature)
                .is_err(),
            "an operation signed by the leaked key must not verify as a rotation"
        );
    }

    #[test]
    fn rotation_keys_can_themselves_be_replaced() {
        let (genesis, _, _, rotation) = a_genesis();
        let cid = operation_cid(&genesis).unwrap();
        let replacement = SigningKey::generate();

        let rotated = rotate_rotation_keys(&genesis, &cid, &[replacement.did_key()], &rotation)
            .expect("rotate rotation keys");

        assert_eq!(rotated.rotation_keys, vec![replacement.did_key()]);
        assert_eq!(rotated.prev.as_deref(), Some(cid.as_str()));
    }

    #[test]
    fn each_operation_has_its_own_cid() {
        // Otherwise `prev` could not distinguish links in the chain.
        let (genesis, _, _, rotation) = a_genesis();
        let cid = operation_cid(&genesis).unwrap();
        let rotated =
            rotate_signing_key(&genesis, &cid, &SigningKey::generate(), &rotation).unwrap();

        assert_ne!(operation_cid(&rotated).unwrap(), cid);
        assert!(
            cid.starts_with("bafyre"),
            "expected a DAG-CBOR CIDv1: {cid}"
        );
    }

    #[test]
    fn the_handle_and_pds_survive_a_signing_key_rotation() {
        // Rotation replaces one field. Losing the handle or the service
        // endpoint would make the member unreachable in a different way.
        let (genesis, _, _, rotation) = a_genesis();
        let cid = operation_cid(&genesis).unwrap();
        let rotated =
            rotate_signing_key(&genesis, &cid, &SigningKey::generate(), &rotation).unwrap();

        assert_eq!(rotated.also_known_as, genesis.also_known_as);
        assert_eq!(rotated.services, genesis.services);
        assert_eq!(rotated.rotation_keys, genesis.rotation_keys);
    }
}

// --- submission ------------------------------------------------------------------

/// Submit a signed operation to the PLC directory.
///
/// **Not gated by the federation switch** (ADR 0016). That switch governs
/// ActivityPub's outbound delivery, where suppression costs a member nothing
/// local. Here it would cost them their entire ATProtocol identity: without a
/// registered DID they cannot be resolved, cannot be followed, and cannot later
/// take elsewhere a DID that was never created.
///
/// Failure is returned, never swallowed. A DID that exists locally and not in
/// the directory is a real and recoverable state — but only if something knows
/// it happened.
pub async fn submit(
    client: &reqwest::Client,
    did: &str,
    signed: &Operation,
) -> Result<(), SubmitError> {
    let response = client
        .post(directory_url(did))
        .json(signed)
        .send()
        .await
        .map_err(|e| SubmitError::Unreachable(e.to_string()))?;

    let status = response.status();
    if status.is_success() {
        return Ok(());
    }

    let body = response.text().await.unwrap_or_default();
    // A 4xx means the directory rejected the operation itself — a bad
    // signature, a `prev` that does not match its head. Retrying verbatim will
    // never help, and the distinction is what tells an operator whether to
    // wait or to look.
    if status.is_client_error() {
        Err(SubmitError::Rejected {
            status: status.as_u16(),
            body,
        })
    } else {
        Err(SubmitError::Unreachable(format!("{status}: {body}")))
    }
}

#[derive(Debug)]
pub enum SubmitError {
    /// The directory could not be reached, or answered 5xx. Retryable.
    Unreachable(String),
    /// The directory refused the operation. Retrying it unchanged will not help.
    Rejected { status: u16, body: String },
}

impl SubmitError {
    /// Is retrying this operation, unchanged, worth doing?
    pub fn is_retryable(&self) -> bool {
        matches!(self, SubmitError::Unreachable(_))
    }
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubmitError::Unreachable(e) => write!(f, "PLC directory unreachable: {e}"),
            SubmitError::Rejected { status, body } => {
                write!(f, "PLC directory rejected the operation ({status}): {body}")
            }
        }
    }
}

impl std::error::Error for SubmitError {}

#[cfg(test)]
mod submit_tests {
    use super::*;

    #[test]
    fn a_rejection_is_not_retryable_but_an_outage_is() {
        // The distinction an operator acts on: wait, or go and look.
        assert!(SubmitError::Unreachable("timed out".into()).is_retryable());
        assert!(
            !SubmitError::Rejected {
                status: 400,
                body: "bad signature".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn the_directory_url_names_the_did() {
        assert_eq!(
            directory_url("did:plc:abc"),
            "https://plc.directory/did:plc:abc"
        );
    }
}
