//! Phase 7 exit criterion: **CAR export validates against an independent
//! implementation.**
//!
//! "Independent" is the operative word. Reading the archive back with atrium
//! would only prove atrium agrees with itself, and that is exactly the failure
//! mode the predecessor's hand-rolled MST and CAR had: structurally wrong,
//! perfectly self-consistent, and rejected by every real consumer.
//!
//! So the archive is parsed by `rs-car-sync` — a different author's CARv1/v2
//! implementation, sharing none of atrium's framing code — with block-hash
//! validation on, which recomputes each block's multihash and checks it against
//! the CID it was filed under. That check is cryptographic rather than
//! structural: a shared library cannot make a mis-encoded block pass it.
//!
//! The one thing both crates do share is the `cid` crate itself, for the CID
//! type. That is unavoidable — it is the ecosystem's single representation —
//! and it is not where encoding bugs live.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_atproto::blocks::PodBlocks;
use brolly_atproto::keys::SigningKey;
use brolly_atproto::repo;
use serde_json::json;

const DID: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";

fn fixture() -> (tempfile::TempDir, brolly_store::StoreManager, uuid::Uuid) {
    let dir = tempfile::tempdir().unwrap();
    let manager = brolly_store::StoreManager::open(dir.path(), 4, 60).unwrap();
    (dir, manager, uuid::Uuid::new_v4())
}

fn blocks(manager: &brolly_store::StoreManager, user: uuid::Uuid) -> PodBlocks {
    PodBlocks::new(manager.repo_blocks(user).unwrap())
}

/// Parse a CAR with an implementation that is not atrium, verifying every
/// block's hash on the way through.
fn parse_independently(car: &[u8]) -> (Vec<(rs_car_sync::Cid, Vec<u8>)>, Vec<rs_car_sync::Cid>) {
    let mut cursor = std::io::Cursor::new(car);
    let (blocks, header) = rs_car_sync::car_read_all(&mut cursor, true)
        .expect("an independent CAR reader must accept the archive");
    (blocks, header.roots)
}

/// A repo with one Bluesky post and one record from a lexicon nobody has mapped.
async fn a_repo_with_two_lexicons(
    manager: &brolly_store::StoreManager,
    user: uuid::Uuid,
) -> (SigningKey, atrium_repo::Cid) {
    let key = SigningKey::generate();
    let (mut root, mut rev) = repo::create(blocks(manager, user), DID, &key)
        .await
        .expect("create");

    for (collection, rkey, record) in [
        (
            "app.bsky.feed.post",
            "3kaaaaaaaaaaa",
            json!({"$type": "app.bsky.feed.post", "text": "a mapped lexicon"}),
        ),
        (
            "site.standard.doc",
            "3kbbbbbbbbbbb",
            json!({
                "$type": "site.standard.doc",
                "text": "a lexicon nobody mapped",
                "nested": {"list": [1, 2, 3], "flag": true},
            }),
        ),
    ] {
        let (_, next, minted) = repo::put_record(
            blocks(manager, user),
            root,
            &key,
            collection,
            rkey,
            &record,
            &rev,
        )
        .await
        .expect("put");
        root = next;
        rev = minted;
    }

    (key, root)
}

#[tokio::test]
async fn an_exported_car_is_accepted_by_an_independent_reader() {
    let (_dir, manager, user) = fixture();
    let (_key, root) = a_repo_with_two_lexicons(&manager, user).await;

    let car = repo::export_car(blocks(&manager, user), root)
        .await
        .expect("export");

    let (parsed, roots) = parse_independently(&car);
    assert!(!parsed.is_empty(), "the archive carried no blocks");
    assert_eq!(roots.len(), 1, "a repo CAR has exactly one root");
    assert_eq!(
        roots[0].to_string(),
        root.to_string(),
        "the CAR root must be the repo's current commit"
    );
}

#[tokio::test]
async fn every_block_hashes_to_the_cid_it_is_filed_under() {
    // `validate_block_hash: true` above already enforces this inside the
    // reader; this asserts it a second way, from our side, so the guarantee
    // does not depend on that flag staying set.
    let (_dir, manager, user) = fixture();
    let (_key, root) = a_repo_with_two_lexicons(&manager, user).await;

    let car = repo::export_car(blocks(&manager, user), root)
        .await
        .expect("export");
    let (parsed, _) = parse_independently(&car);

    use sha2::{Digest, Sha256};
    for (cid, block) in &parsed {
        assert_eq!(
            cid.hash().digest(),
            &Sha256::digest(block)[..],
            "block {cid} does not hash to its own CID"
        );
    }
}

#[tokio::test]
async fn the_archive_carries_every_reachable_block_and_no_more() {
    // A CAR missing a block is an archive that cannot be replayed; one
    // carrying unreachable blocks leaks whatever they held.
    let (_dir, manager, user) = fixture();
    let (_key, root) = a_repo_with_two_lexicons(&manager, user).await;

    let expected = repo::reachable(blocks(&manager, user), root)
        .await
        .expect("reachable");
    let car = repo::export_car(blocks(&manager, user), root)
        .await
        .expect("export");
    let (parsed, _) = parse_independently(&car);

    let exported: std::collections::BTreeSet<String> =
        parsed.iter().map(|(cid, _)| cid.to_string()).collect();
    let reachable: std::collections::BTreeSet<String> =
        expected.iter().map(|cid| cid.to_string()).collect();

    assert_eq!(
        exported, reachable,
        "the archive and the reachable set disagree"
    );
}

#[tokio::test]
async fn an_unmapped_third_party_lexicon_appears_in_the_export() {
    // Phase 7's third exit criterion, end to end: a lexicon with no mapping
    // round-trips *and* shows up in the archive — which is what makes the
    // export a real data export rather than a Bluesky-shaped subset.
    let (_dir, manager, user) = fixture();
    let (_key, root) = a_repo_with_two_lexicons(&manager, user).await;

    let car = repo::export_car(blocks(&manager, user), root)
        .await
        .expect("export");
    let (parsed, _) = parse_independently(&car);

    // The record body is DAG-CBOR; its field names survive as readable bytes,
    // which is enough to locate it without decoding through atrium again.
    let found = parsed
        .iter()
        .any(|(_, block)| String::from_utf8_lossy(block).contains("a lexicon nobody mapped"));
    assert!(
        found,
        "the unmapped lexicon's record is missing from the archive"
    );

    let mapped = parsed
        .iter()
        .any(|(_, block)| String::from_utf8_lossy(block).contains("a mapped lexicon"));
    assert!(mapped, "the mapped lexicon's record is missing too");
}

#[tokio::test]
async fn an_export_of_an_empty_repo_is_still_a_valid_archive() {
    // A member who has never posted must still be able to export.
    let (_dir, manager, user) = fixture();
    let key = SigningKey::generate();
    let (root, _rev) = repo::create(blocks(&manager, user), DID, &key)
        .await
        .expect("create");

    let car = repo::export_car(blocks(&manager, user), root)
        .await
        .expect("export");
    let (parsed, roots) = parse_independently(&car);

    assert_eq!(roots[0].to_string(), root.to_string());
    assert!(
        !parsed.is_empty(),
        "even an empty repo carries its commit block"
    );
}

#[tokio::test]
async fn a_truncated_archive_is_rejected() {
    // Confirms the independent reader is actually inspecting the bytes rather
    // than accepting anything handed to it — otherwise the tests above prove
    // nothing.
    let (_dir, manager, user) = fixture();
    let (_key, root) = a_repo_with_two_lexicons(&manager, user).await;

    let car = repo::export_car(blocks(&manager, user), root)
        .await
        .expect("export");
    let truncated = &car[..car.len() / 2];

    let mut cursor = std::io::Cursor::new(truncated);
    assert!(
        rs_car_sync::car_read_all(&mut cursor, true).is_err(),
        "a truncated archive must not parse"
    );
}

#[tokio::test]
async fn a_corrupted_block_is_rejected() {
    // The cryptographic half of the check, proven to bite: flip a byte in the
    // block region and the reader must refuse it.
    let (_dir, manager, user) = fixture();
    let (_key, root) = a_repo_with_two_lexicons(&manager, user).await;

    let car = repo::export_car(blocks(&manager, user), root)
        .await
        .expect("export");
    let mut corrupted = car.clone();
    // Well past the header, inside a block body.
    let target = corrupted.len() - 8;
    corrupted[target] ^= 0xff;

    let mut cursor = std::io::Cursor::new(corrupted.as_slice());
    assert!(
        rs_car_sync::car_read_all(&mut cursor, true).is_err(),
        "a block that does not match its CID must be rejected"
    );
}
