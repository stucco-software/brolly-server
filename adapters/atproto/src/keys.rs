//! Repo signing keys.
//!
//! secp256k1, because that is what ATProtocol commits are signed with, and the
//! `atproto_signing` slot in `user_keys` has been waiting for them since the
//! schema was written.
//!
//! **atrium never sees a private key.** ADR 0002 makes this a property of the
//! adoption rather than a hope: `RepoBuilder::bytes()` hands out the commit
//! payload and `finalize(sig)` takes a signature back, so signing happens here
//! and key storage, rotation and PLC stay entirely ours. That is what keeps a
//! future key rotation a local decision instead of an upstream feature request.

use atrium_crypto::keypair::{Did as DidKey, Export, Secp256k1Keypair};
use brolly_identity::db::DbError;

/// Purpose tag in `user_keys` for the key that signs repo commits.
pub const ATPROTO_SIGNING: &str = "atproto_signing";

/// Purpose tag for the key that authorizes PLC operations.
///
/// Deliberately a different key from the signing one. The signing key is used
/// on every commit and is the likelier of the two to leak; recovery means
/// rotating it with a key that was never in that path, so a single key serving
/// both purposes would make a compromise unrecoverable.
pub const ATPROTO_ROTATION: &str = "atproto_rotation";

/// A member's repo signing key.
pub struct SigningKey {
    inner: Secp256k1Keypair,
}

impl SigningKey {
    /// Generate a fresh key.
    pub fn generate() -> Self {
        Self {
            inner: Secp256k1Keypair::create(&mut rand::thread_rng()),
        }
    }

    /// Load from stored bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DbError> {
        Secp256k1Keypair::import(bytes)
            .map(|inner| Self { inner })
            .map_err(|e| DbError::Hash(format!("import signing key: {e}")))
    }

    /// The private scalar, for storage. The only place it is ever exposed.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.export()
    }

    /// The `did:key` form of the public half.
    ///
    /// This is what goes in the PLC document and what a verifier resolves to
    /// check a commit signature.
    pub fn did_key(&self) -> String {
        self.inner.did()
    }

    /// Sign a commit payload.
    pub fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, DbError> {
        self.inner
            .sign(payload)
            .map_err(|e| DbError::Hash(format!("sign commit: {e}")))
    }
}

/// The `(private, public)` pair `identity` stores.
///
/// The public half is the `did:key` string rather than raw bytes, because that
/// is the form every consumer wants — PLC documents, verification, and the
/// `describeRepo` response all want the DID, and re-deriving it on each read
/// would be work to produce something we already had.
pub fn generate_pair() -> Result<(Vec<u8>, Vec<u8>), DbError> {
    let key = SigningKey::generate();
    Ok((key.to_bytes(), key.did_key().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use atrium_crypto::verify::verify_signature;

    #[test]
    fn a_key_survives_export_and_import() {
        // The property storage depends on: a key written to `user_keys` and
        // read back must sign identically, or every commit after a restart
        // fails verification.
        let key = SigningKey::generate();
        let restored = SigningKey::from_bytes(&key.to_bytes()).expect("import");
        assert_eq!(key.did_key(), restored.did_key());
    }

    #[test]
    fn a_signature_verifies_against_the_did_key() {
        let key = SigningKey::generate();
        let payload = b"commit bytes, as atrium would hand them over";
        let signature = key.sign(payload).expect("sign");

        assert!(
            verify_signature(&key.did_key(), payload, &signature).is_ok(),
            "a commit signed with this key must verify against its published DID"
        );
    }

    #[test]
    fn a_tampered_payload_does_not_verify() {
        let key = SigningKey::generate();
        let signature = key.sign(b"the original bytes").expect("sign");

        assert!(
            verify_signature(&key.did_key(), b"the tampered bytes", &signature).is_err(),
            "a flipped byte must invalidate the signature"
        );
    }

    #[test]
    fn another_key_cannot_forge_a_signature() {
        let key = SigningKey::generate();
        let impostor = SigningKey::generate();
        let payload = b"commit bytes";
        let signature = impostor.sign(payload).expect("sign");

        assert!(
            verify_signature(&key.did_key(), payload, &signature).is_err(),
            "one member's key must not validate another's commits"
        );
    }

    #[test]
    fn two_members_never_share_a_key() {
        assert_ne!(
            SigningKey::generate().did_key(),
            SigningKey::generate().did_key()
        );
    }

    #[test]
    fn the_did_key_is_a_secp256k1_did() {
        // `zQ3s…` is the multibase prefix for secp256k1. A did:key of the wrong
        // curve would be rejected by every verifier in the network.
        let did = SigningKey::generate().did_key();
        assert!(did.starts_with("did:key:zQ3s"), "got {did}");
    }

    #[test]
    fn the_stored_pair_round_trips_through_storage_shape() {
        let (private, public) = generate_pair().expect("generate");
        let key = SigningKey::from_bytes(&private).expect("import");
        assert_eq!(key.did_key().as_bytes(), public.as_slice());
    }
}
