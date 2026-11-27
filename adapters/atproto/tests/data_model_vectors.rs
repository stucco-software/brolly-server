//! The atproto-interop-tests data-model vectors (stage 4a, H1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD_INDIFFERENT;
use brolly_atproto::data_model;
use ipld_core::cid::Cid;
use serde_json::Value;
use sha2::Digest;

const SHA2_256: u64 = 0x12;
const DAG_CBOR: u64 = 0x71;

/// The CID of a DAG-CBOR block: CIDv1, dag-cbor, sha-256.
fn cid_for_cbor(bytes: &[u8]) -> Cid {
    let digest = sha2::Sha256::digest(bytes);
    let hash = ipld_core::cid::multihash::Multihash::<64>::wrap(SHA2_256, &digest).unwrap();
    Cid::new_v1(DAG_CBOR, hash)
}

fn vectors(name: &str) -> Vec<Value> {
    let path = format!(
        "{}/tests/fixtures/interop/data-model/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn every_valid_vector_converts() {
    for v in vectors("data-model-valid.json") {
        data_model::record_from_json(&v["json"]).unwrap_or_else(|e| panic!("{}: {e}", v["note"]));
    }
}

#[test]
fn every_invalid_vector_is_refused() {
    for v in vectors("data-model-invalid.json") {
        assert!(
            data_model::record_from_json(&v["json"]).is_err(),
            "{} was accepted",
            v["note"]
        );
    }
}

#[test]
fn every_fixture_encodes_to_its_bytes_and_cid_and_reads_back() {
    for v in vectors("data-model-fixtures.json") {
        let ipld = data_model::record_from_json(&v["json"]).unwrap();
        let bytes = serde_ipld_dagcbor::to_vec(&ipld).unwrap();
        let expected = STANDARD_NO_PAD_INDIFFERENT
            .decode(v["cbor_base64"].as_str().unwrap())
            .unwrap();
        assert_eq!(bytes, expected, "CBOR for {}", v["json"]);
        assert_eq!(cid_for_cbor(&bytes).to_string(), v["cid"].as_str().unwrap());
        assert_eq!(data_model::to_json(&ipld), v["json"], "read-back");
    }
}
