//! The record envelope (stage 4a, H2): what every write's record passes
//! through before a block is made of it — the seed of chunk 4's gate.
//!
//! In order: the record is an object; `$type` is filled with the collection
//! when missing and refused when it names another (the reference's rule,
//! under any `validate`); then the data model (`data_model`). This is the only
//! place a `$type` is filled — the write handlers no longer do it. A record
//! must name its own type because the pod's faithful layer keys every field
//! under it; without one, its fields would collide with another lexicon's.

use atrium_api::types::string::Nsid;
use ipld_core::ipld::Ipld;
use serde_json::Value;

use crate::data_model;
use crate::repo::RepoError;

/// Hold `record` to the envelope and the data model; the IPLD to commit.
pub fn prepare(collection: &Nsid, record: &Value) -> Result<Ipld, RepoError> {
    let Value::Object(fields) = record else {
        return Err(RepoError::InvalidRecord("record must be an object".into()));
    };
    let mut fields = fields.clone();
    match fields.get("$type") {
        None => {
            fields.insert("$type".into(), Value::String(collection.as_str().into()));
        }
        Some(Value::String(t)) if t == collection.as_str() => {}
        Some(Value::String(t)) => {
            return Err(RepoError::InvalidRecord(format!(
                "Invalid $type: expected {}, got {t}",
                collection.as_str()
            )));
        }
        Some(_) => {
            return Err(RepoError::InvalidRecord(
                "record/$type: $type must be a non-empty string".into(),
            ));
        }
    }
    data_model::record_from_json(&Value::Object(fields))
        .map_err(|e| RepoError::InvalidRecord(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn post() -> Nsid {
        Nsid::new("app.bsky.feed.post".into()).unwrap()
    }

    #[test]
    fn a_record_that_is_not_an_object_is_refused_not_panicked() {
        for value in [
            json!("blah"),
            json!(1),
            json!([1]),
            json!(null),
            json!(true),
        ] {
            assert!(prepare(&post(), &value).is_err(), "{value}");
        }
    }

    #[test]
    fn a_missing_type_is_filled_with_the_collection() {
        let ipld = prepare(&post(), &json!({"text": "hi"})).unwrap();
        assert_eq!(
            crate::data_model::to_json(&ipld)["$type"],
            "app.bsky.feed.post"
        );
    }

    #[test]
    fn a_different_type_is_refused_with_the_references_message() {
        let err = prepare(&post(), &json!({"$type": "app.bsky.feed.like"})).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid $type: expected app.bsky.feed.post, got app.bsky.feed.like"
        );
    }

    #[test]
    fn a_type_that_is_not_a_string_is_refused() {
        let err = prepare(&post(), &json!({"$type": 1})).unwrap_err();
        assert_eq!(
            err.to_string(),
            "record/$type: $type must be a non-empty string"
        );
    }

    #[test]
    fn the_data_model_applies_inside() {
        assert!(prepare(&post(), &json!({"n": 1.5})).is_err());
    }
}
