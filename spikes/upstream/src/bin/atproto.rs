//! Spike probe — ATProtocol via `atrium-*`.
//!
//! Open decision O1. Proves the end-to-end path the plan demands before we
//! commit to these crates: **BYO storage**, **BYO key**, **write a record**,
//! **sign a commit**, **verify the signature**.
//!
//! Run: `cargo run -p spike-upstream --bin atproto`
//!
//! The previous project's adopt-upstream effort built its verdict table from
//! line counts, and four of eleven proposed swaps turned out to be no-ops.
//! This file exists so that cannot happen again.

use std::collections::HashMap;

use atrium_api::types::string::Did;
use atrium_crypto::keypair::{Did as DidKey, Export, Secp256k1Keypair};
use atrium_crypto::verify::verify_signature;
use atrium_repo::blockstore::{AsyncBlockStoreRead, AsyncBlockStoreWrite, Error as BsError};
use atrium_repo::{Cid, Repository};

/// A block store we own entirely, to prove the trait boundary is real.
///
/// This is the shape our per-user Oxigraph/Postgres store would implement. If
/// these two methods are the whole contract, storage is genuinely pluggable —
/// constraint C1 in the old research, which was marked PASS but whose
/// implementation sub-plan then had to be rewritten.
#[derive(Default)]
struct OurBlockStore {
    blocks: HashMap<Cid, Vec<u8>>,
    writes: usize,
}

impl AsyncBlockStoreRead for OurBlockStore {
    async fn read_block_into(&mut self, cid: Cid, contents: &mut Vec<u8>) -> Result<(), BsError> {
        let block = self.blocks.get(&cid).ok_or(BsError::CidNotFound)?;
        contents.clear();
        contents.extend_from_slice(block);
        Ok(())
    }
}

impl AsyncBlockStoreWrite for OurBlockStore {
    async fn write_block(
        &mut self,
        codec: u64,
        hash: u64,
        contents: &[u8],
    ) -> Result<Cid, BsError> {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(contents);
        let mh = atrium_repo::Multihash::wrap(hash, &digest).expect("wrap multihash");
        let cid = Cid::new_v1(codec, mh);
        self.blocks.insert(cid, contents.to_vec());
        self.writes += 1;
        Ok(cid)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut check = |name: &str, ok: bool, detail: String| {
        if ok {
            pass += 1;
            println!("  PASS  {name:<34} {detail}");
        } else {
            fail += 1;
            println!("  FAIL  {name:<34} {detail}");
        }
    };

    println!("\natrium-* end-to-end probe (open decision O1)\n");

    // --- BYO key ----------------------------------------------------------
    let keypair = Secp256k1Keypair::create(&mut rand::thread_rng());
    let exported = keypair.export();
    let reimported = Secp256k1Keypair::import(&exported)?;
    check(
        "BYO key: export/import round-trip",
        reimported.export() == exported,
        format!("{} bytes", exported.len()),
    );

    let did_key = keypair.did();
    check(
        "did:key derivation",
        did_key.starts_with("did:key:z"),
        did_key.clone(),
    );

    // --- write a record ---------------------------------------------------
    let did = Did::new("did:plc:spike00000000000000000000".to_string())?;
    let store = OurBlockStore::default();
    let builder = Repository::create(store, did.clone()).await?;

    // Sign the genesis commit with our own key — atrium hands us bytes and
    // takes back a signature; it never sees the private key.
    let genesis_bytes = builder.bytes();
    let genesis_sig = keypair.sign(&genesis_bytes)?;
    check(
        "commit bytes exposed for signing",
        !genesis_bytes.is_empty(),
        format!("{} bytes to sign", genesis_bytes.len()),
    );

    let mut repo = builder.finalize(genesis_sig.clone()).await?;
    check(
        "genesis commit finalized",
        true,
        format!("root {}", repo.root()),
    );

    check(
        "signature verifies via atrium",
        verify_signature(&did_key, &genesis_bytes, &genesis_sig).is_ok(),
        "verify_signature(did:key, bytes, sig)".to_string(),
    );

    let tampered = {
        let mut b = genesis_bytes.clone();
        b[0] ^= 0xff;
        b
    };
    check(
        "tampered payload is rejected",
        verify_signature(&did_key, &tampered, &genesis_sig).is_err(),
        "flipped one byte".to_string(),
    );

    // --- add a record and commit -----------------------------------------
    let record = serde_json::json!({
        "$type": "app.bsky.feed.post",
        "text": "written by the brolly spike",
        "createdAt": "2026-08-18T12:00:00Z",
    });

    let (commit_builder, record_cid) = repo
        .add_raw("app.bsky.feed.post/3kspike000000", &record)
        .await?;

    let commit_bytes = commit_builder.bytes();
    let commit_sig = keypair.sign(&commit_bytes)?;
    // CommitBuilder::finalize returns the new root CID; the Repository stays live.
    let new_root = commit_builder.finalize(commit_sig.clone()).await?;

    check(
        "record written, CID returned",
        record_cid.to_string().starts_with("bafy"),
        record_cid.to_string(),
    );
    check(
        "second commit signed + finalized",
        verify_signature(&did_key, &commit_bytes, &commit_sig).is_ok(),
        format!("new root {new_root}"),
    );

    // --- read it back through our own store -------------------------------
    let read_back: Option<serde_json::Value> =
        repo.get_raw("app.bsky.feed.post/3kspike000000").await?;
    check(
        "record reads back through our blockstore",
        read_back.as_ref().and_then(|v| v.get("text"))
            == Some(&serde_json::json!("written by the brolly spike")),
        format!("{:?}", read_back.as_ref().and_then(|v| v.get("text"))),
    );

    println!("\n  {pass} passed, {fail} failed\n");
    if fail > 0 {
        std::process::exit(1);
    }
    Ok(())
}
