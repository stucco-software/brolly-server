//! Actor signing keys.
//!
//! RSA-2048, because cavage-09 HTTP signatures are what the fediverse verifies
//! and Mastodon accepts nothing else. That choice is the reason this lives in
//! the ActivityPub adapter rather than in `brolly-identity`: the algorithm is a
//! protocol constraint, not an identity one, and `identity` stores whatever PEM
//! it is handed without knowing what made it.
//!
//! It is also where RUSTSEC-2023-0071 enters the tree. The exposure is
//! accepted in `deny.toml` with the reasoning written out: our RSA private-key
//! use is outbound signing, not a decryption oracle, and the Marvin attack
//! needs an attacker who can induce and finely time many private-key
//! operations.

use activitypub_federation::http_signatures::generate_actor_keypair;
use brolly_identity::db::DbError;

/// Generate a keypair, in the `(private, public)` PEM shape `identity` stores.
///
/// Errors are mapped onto `DbError` because that is the signature
/// `identity::instance` takes for its generator, and inventing a second error
/// type for "the caller's closure failed" would be threaded through every call
/// site to be immediately discarded.
pub fn generate() -> Result<(String, String), DbError> {
    let keypair =
        generate_actor_keypair().map_err(|e| DbError::Hash(format!("actor keypair: {e}")))?;
    Ok((keypair.private_key, keypair.public_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_keypair_is_pem_and_distinct_each_time() {
        let (private, public) = generate().expect("generate");

        // PKCS#8 private, SPKI public — the shapes the framework's signer and
        // every remote verifier expect.
        assert!(private.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(public.starts_with("-----BEGIN PUBLIC KEY-----"));

        let (other, _) = generate().expect("generate again");
        assert_ne!(
            private, other,
            "two actors must never be issued the same key"
        );
    }
}
