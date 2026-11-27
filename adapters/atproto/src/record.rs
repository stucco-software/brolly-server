//! The gate (stage 4a, H2, H5): what every write's record passes through
//! before a block is made of it.
//!
//! In order: the record is an object; `$type` is filled with the collection
//! when missing and refused when it names another (the reference's rule,
//! under any `validate`); the data model (`data_model`); then the record's
//! lexicon (`lexicon`), against the **normalised** value, so what is
//! validated is what is committed (Decision F). This is the only place a
//! `$type` is filled. A record must name its own type because the pod's
//! faithful layer keys every field under it.
//!
//! Part c (ADR 0022) wraps this behind a protocol-neutral container hook;
//! nothing ATProto-typed crosses into the core.

use atrium_api::types::string::{Nsid, RecordKey};
use ipld_core::ipld::Ipld;
use serde_json::Value;

use crate::data_model;
use crate::lexicon::{self, Refusal, Status};
use crate::repo::RepoError;

/// What a write asked for, as the lexicons define `validate` (H5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validate {
    /// `validate: true` — an unknown lexicon is refused.
    Required,
    /// `validate: false` — the reference skips validation; brolly still
    /// validates a known lexicon (Decision E), so this differs from
    /// `Optimistic` only in name.
    Skip,
    /// `validate` absent — known lexicons validated, unknown accepted.
    Optimistic,
}

impl Validate {
    /// The wire's optional boolean.
    pub fn from_param(validate: Option<bool>) -> Self {
        match validate {
            Some(true) => Validate::Required,
            Some(false) => Validate::Skip,
            None => Validate::Optimistic,
        }
    }
}

fn lexicons() -> Result<&'static lexicon::Registry, RepoError> {
    // Forced at startup, so this does not fail in a running server; if it
    // did, the fault is ours, not the client's.
    lexicon::vendored().map_err(|e| RepoError::Lexicon(e.to_string()))
}

/// H2 and H5: envelope, data model, lexicon. The IPLD to commit and the
/// status to answer with. `rkey` is `None` for a create that has not
/// minted one; `apply` runs [`check_key`] once it has.
pub fn check_record(
    collection: &Nsid,
    rkey: Option<&RecordKey>,
    record: &Value,
    validate: Validate,
) -> Result<(Ipld, Status), RepoError> {
    let ipld = envelope(collection, record)?;
    let normalised = data_model::to_json(&ipld);
    let status = lexicons()?
        .validate(collection.as_str(), rkey.map(|r| r.as_str()), &normalised)
        .map_err(|why| refused(collection, why))?;
    if status == Status::Unknown && validate == Validate::Required {
        return Err(RepoError::InvalidRecord(format!(
            "Unknown lexicon type: {}",
            collection.as_str()
        )));
    }
    Ok((ipld, status))
}

/// The lexicon's `key` type against an rkey (H5).
pub fn check_key(collection: &Nsid, rkey: &RecordKey) -> Result<(), RepoError> {
    lexicons()?
        .check_key(collection.as_str(), rkey.as_str())
        .map_err(|why| refused(collection, why))
}

/// A refusal as the write path answers it: the client's fault is an invalid
/// record (400 on the wire); a broken lexicon of ours is a server error.
fn refused(collection: &Nsid, why: Refusal) -> RepoError {
    match why {
        Refusal::Record(_) | Refusal::Key(_) | Refusal::NotARecord(_) => {
            RepoError::InvalidRecord(format!("Invalid {} record: {why}", collection.as_str()))
        }
        Refusal::Lexicon(m) => RepoError::Lexicon(m),
    }
}

/// The envelope and the data model (H1, H2).
fn envelope(collection: &Nsid, record: &Value) -> Result<Ipld, RepoError> {
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

/// Until `PlannedWrite` moves to [`check_record`] (the next task).
pub fn prepare(collection: &Nsid, record: &Value) -> Result<Ipld, RepoError> {
    envelope(collection, record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn nsid(s: &str) -> Nsid {
        Nsid::new(s.into()).unwrap()
    }

    fn rkey(s: &str) -> RecordKey {
        RecordKey::new(s.into()).unwrap()
    }

    const CREATED: &str = "2026-11-27T00:00:00.000Z";

    fn a_post() -> Value {
        json!({"$type": "app.bsky.feed.post", "text": "hi", "createdAt": CREATED})
    }

    fn a_bad_post() -> Value {
        json!({"$type": "app.bsky.feed.post", "text": "hi"})
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
            assert!(
                check_record(
                    &nsid("app.bsky.feed.post"),
                    None,
                    &value,
                    Validate::Optimistic
                )
                .is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn a_missing_type_is_filled_with_the_collection() {
        let (ipld, status) = check_record(
            &nsid("com.example.thing"),
            None,
            &json!({"text": "hi"}),
            Validate::Optimistic,
        )
        .unwrap();
        assert_eq!(
            crate::data_model::to_json(&ipld)["$type"],
            "com.example.thing"
        );
        assert_eq!(status, Status::Unknown);
    }

    #[test]
    fn a_different_type_is_refused_under_every_validate() {
        for validate in [Validate::Required, Validate::Skip, Validate::Optimistic] {
            let err = check_record(
                &nsid("app.bsky.feed.post"),
                None,
                &json!({"$type": "app.bsky.feed.like"}),
                validate,
            )
            .unwrap_err();
            assert_eq!(
                err.to_string(),
                "Invalid $type: expected app.bsky.feed.post, got app.bsky.feed.like"
            );
        }
    }

    #[test]
    fn a_type_that_is_not_a_string_is_refused() {
        let err = check_record(
            &nsid("com.example.thing"),
            None,
            &json!({"$type": 1}),
            Validate::Optimistic,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "record/$type: $type must be a non-empty string"
        );
    }

    #[test]
    fn the_data_model_applies_inside_under_every_validate() {
        for validate in [Validate::Required, Validate::Skip, Validate::Optimistic] {
            assert!(
                check_record(
                    &nsid("com.example.thing"),
                    None,
                    &json!({"n": 1.5}),
                    validate
                )
                .is_err()
            );
        }
    }

    // Decision E's table, cell by cell.

    #[test]
    fn known_and_valid_is_valid_under_every_validate() {
        for validate in [Validate::Required, Validate::Skip, Validate::Optimistic] {
            let (_, status) =
                check_record(&nsid("app.bsky.feed.post"), None, &a_post(), validate).unwrap();
            assert_eq!(status, Status::Valid);
        }
    }

    #[test]
    fn known_and_invalid_is_refused_under_every_validate_even_false() {
        for validate in [Validate::Required, Validate::Skip, Validate::Optimistic] {
            let err = check_record(&nsid("app.bsky.feed.post"), None, &a_bad_post(), validate)
                .unwrap_err();
            assert_eq!(
                err.to_string(),
                "Invalid app.bsky.feed.post record: record must have the property \"createdAt\""
            );
        }
    }

    #[test]
    fn unknown_is_accepted_unless_validation_is_required() {
        let thing = json!({"$type": "com.example.thing", "x": 1});
        for validate in [Validate::Skip, Validate::Optimistic] {
            let (_, status) =
                check_record(&nsid("com.example.thing"), None, &thing, validate).unwrap();
            assert_eq!(status, Status::Unknown);
        }
        let err =
            check_record(&nsid("com.example.thing"), None, &thing, Validate::Required).unwrap_err();
        assert_eq!(err.to_string(), "Unknown lexicon type: com.example.thing");
    }

    #[test]
    fn the_validate_parameter_maps_to_the_table() {
        assert_eq!(Validate::from_param(Some(true)), Validate::Required);
        assert_eq!(Validate::from_param(Some(false)), Validate::Skip);
        assert_eq!(Validate::from_param(None), Validate::Optimistic);
    }

    #[test]
    fn a_known_rkey_is_held_to_the_key_type() {
        let profile = json!({"$type": "app.bsky.actor.profile"});
        let collection = nsid("app.bsky.actor.profile");
        assert!(
            check_record(
                &collection,
                Some(&rkey("self")),
                &profile,
                Validate::Optimistic
            )
            .is_ok()
        );
        let err = check_record(
            &collection,
            Some(&rkey("3kaaaaaaaaaab")),
            &profile,
            Validate::Optimistic,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid app.bsky.actor.profile record: record key 3kaaaaaaaaaab is not self"
        );
        assert!(check_key(&collection, &rkey("3kaaaaaaaaaab")).is_err());
        assert!(check_key(&collection, &rkey("self")).is_ok());
    }

    #[test]
    fn a_valid_like_with_a_strong_ref_passes_validate_true() {
        let like = json!({
            "$type": "app.bsky.feed.like",
            "subject": {"uri": "at://did:plc:abc/app.bsky.feed.post/3kaaaaaaaaaab",
                        "cid": "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a"},
            "createdAt": CREATED,
        });
        assert!(check_record(&nsid("app.bsky.feed.like"), None, &like, Validate::Required).is_ok());
    }

    #[test]
    fn a_collection_that_is_not_a_record_type_is_the_clients_fault() {
        let err = check_record(
            &nsid("com.atproto.repo.strongRef"),
            None,
            &json!({}),
            Validate::Skip,
        )
        .unwrap_err();
        assert!(matches!(err, RepoError::InvalidRecord(_)), "{err:?}");
        assert_eq!(
            err.to_string(),
            "Invalid com.atproto.repo.strongRef record: com.atproto.repo.strongRef is not a record type"
        );
    }

    #[test]
    fn a_broken_lexicon_is_our_fault_not_the_clients() {
        let collection = nsid("app.bsky.feed.post");
        let err = refused(
            &collection,
            Refusal::Lexicon("a ref that does not resolve".into()),
        );
        assert!(matches!(err, RepoError::Lexicon(_)), "{err:?}");
        assert_eq!(err.to_string(), "lexicon: a ref that does not resolve");
        for client in [
            Refusal::Record("record/text must be a string".into()),
            Refusal::Key("record key x is not self".into()),
            Refusal::NotARecord("app.bsky.feed.post".into()),
        ] {
            assert!(matches!(
                refused(&collection, client),
                RepoError::InvalidRecord(_)
            ));
        }
    }
}
