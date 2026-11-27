//! The ATProto data model's JSON mapping, both ways (stage 4a, H1).
//!
//! One place turns wire JSON into the IPLD a record block is made of, and
//! back. The rules are the data model's own, held to the atproto-interop-tests
//! vectors (`tests/data_model_vectors.rs`):
//!
//! * `{"$link": "<cid>"}` is a CID link and `{"$bytes": "<base64>"}` is bytes,
//!   anywhere in a record; either with any other key, or a value of the wrong
//!   kind, is refused. A link must be the canonical string of a CIDv1, so what
//!   is written reads back byte-identical.
//! * There are no floats. A number whose nearest double is integral and within
//!   i64 is that integer (`123.0`, `1e3`) — every JSON client reads it so, and
//!   the vectors call it valid; anything else is refused.
//! * `$type`, wherever it appears, is a non-empty string.
//! * A blob is `{"$type": "blob", "ref": {"$link"}, "mimeType", "size"}` with
//!   exactly those four fields, its `ref` a raw sha-256 CIDv1. The legacy
//!   `{"cid", "mimeType"}` form is never written.
//!
//! Reads emit `$link` and `$bytes` (base64, no padding). A float stored before
//! these rules still reads back as a JSON number.
//!
//! Paths in errors are built only when an error is, from a borrowed chain, so
//! converting a large record costs no allocation per node.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, STANDARD_NO_PAD_INDIFFERENT};
use ipld_core::cid::{Cid, Version};
use ipld_core::ipld::Ipld;
use serde_json::{Map, Number, Value};

/// The multicodec for raw bytes: what a blob's CID names.
const RAW: u64 = 0x55;
/// The multihash code for sha-256.
const SHA2_256: u64 = 0x12;
/// Keys longer than this are cut when echoed in an error path.
const KEY_ECHO: usize = 64;
/// Paths deeper than this show `…` and only the last `MAX_SEGMENTS - 1`.
const MAX_SEGMENTS: usize = 16;

/// Why a value is not in the data model: the path to it, and what is wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataModelError {
    pub path: String,
    pub reason: String,
}

impl std::fmt::Display for DataModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.reason)
    }
}

impl std::error::Error for DataModelError {}

enum Seg<'a> {
    Root,
    Key(&'a str),
    Index(usize),
}

/// A position in a record, as a chain borrowed up the call stack.
struct At<'a> {
    up: Option<&'a At<'a>>,
    seg: Seg<'a>,
}

impl At<'_> {
    fn root() -> At<'static> {
        At {
            up: None,
            seg: Seg::Root,
        }
    }

    fn key<'b>(&'b self, key: &'b str) -> At<'b> {
        At {
            up: Some(self),
            seg: Seg::Key(key),
        }
    }

    fn index(&self, i: usize) -> At<'_> {
        At {
            up: Some(self),
            seg: Seg::Index(i),
        }
    }

    fn render(&self) -> String {
        let mut segs = Vec::new();
        let mut at = Some(self);
        while let Some(node) = at {
            if !matches!(node.seg, Seg::Root) {
                segs.push(&node.seg);
            }
            at = node.up;
        }
        segs.reverse();
        let mut out = String::from("record");
        let shown = if segs.len() > MAX_SEGMENTS {
            out.push_str("/…");
            &segs[segs.len() - (MAX_SEGMENTS - 1)..]
        } else {
            &segs[..]
        };
        for seg in shown {
            out.push('/');
            match seg {
                Seg::Root => {}
                Seg::Index(i) => out.push_str(&i.to_string()),
                Seg::Key(k) => {
                    for (n, c) in k.chars().enumerate() {
                        if n == KEY_ECHO {
                            out.push('…');
                            break;
                        }
                        match c {
                            '~' => out.push_str("~0"),
                            '/' => out.push_str("~1"),
                            c => out.push(c),
                        }
                    }
                }
            }
        }
        out
    }

    fn refuse(&self, reason: &str) -> DataModelError {
        DataModelError {
            path: self.render(),
            reason: reason.into(),
        }
    }
}

/// A record: the data model, and an object at the top.
pub fn record_from_json(value: &Value) -> Result<Ipld, DataModelError> {
    if !value.is_object() {
        return Err(At::root().refuse("must be an object"));
    }
    from_json(value)
}

/// Any value in the data model.
pub(crate) fn from_json(value: &Value) -> Result<Ipld, DataModelError> {
    convert(value, &At::root())
}

fn convert(value: &Value, at: &At) -> Result<Ipld, DataModelError> {
    match value {
        Value::Null => Ok(Ipld::Null),
        Value::Bool(b) => Ok(Ipld::Bool(*b)),
        Value::Number(n) => number(n, at),
        Value::String(s) => Ok(Ipld::String(s.clone())),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(i, item)| convert(item, &at.index(i)))
            .collect::<Result<Vec<_>, _>>()
            .map(Ipld::List),
        Value::Object(fields) => object(fields, at),
    }
}

fn number(n: &Number, at: &At) -> Result<Ipld, DataModelError> {
    const TOO_BIG: &str = "integers are limited to 64-bit signed";
    if let Some(i) = n.as_i64() {
        return Ok(Ipld::Integer(i.into()));
    }
    if n.as_u64().is_some() {
        return Err(at.refuse(TOO_BIG));
    }
    match n.as_f64() {
        Some(f) if f.is_finite() && f.fract() == 0.0 => {
            // `i64::MAX as f64` is 2^63, one past the largest i64, so `<` is exact.
            if f >= i64::MIN as f64 && f < i64::MAX as f64 {
                Ok(Ipld::Integer((f as i64).into()))
            } else {
                Err(at.refuse(TOO_BIG))
            }
        }
        _ => Err(at.refuse("floats are not allowed")),
    }
}

fn object(fields: &Map<String, Value>, at: &At) -> Result<Ipld, DataModelError> {
    if let Some(link) = fields.get("$link") {
        if fields.len() != 1 {
            return Err(at.refuse("$link must be the only key"));
        }
        return link_of(link, at).map(Ipld::Link);
    }
    if let Some(bytes) = fields.get("$bytes") {
        if fields.len() != 1 {
            return Err(at.refuse("$bytes must be the only key"));
        }
        let Value::String(text) = bytes else {
            return Err(at.refuse("$bytes must be a base64 string"));
        };
        return STANDARD_NO_PAD_INDIFFERENT
            .decode(text)
            .map(Ipld::Bytes)
            .map_err(|_| at.refuse("$bytes is not base64"));
    }
    match fields.get("$type") {
        None if is_legacy_blob(fields) => {
            return Err(at.refuse("legacy blob refs are not allowed"));
        }
        None => {}
        Some(Value::String(t)) if t == "blob" => return blob(fields, at),
        Some(Value::String(t)) if !t.is_empty() => {}
        Some(_) => return Err(at.refuse("$type must be a non-empty string")),
    }
    let mut out = BTreeMap::new();
    for (name, field) in fields {
        out.insert(name.clone(), convert(field, &at.key(name))?);
    }
    Ok(Ipld::Map(out))
}

fn link_of(value: &Value, at: &At) -> Result<Cid, DataModelError> {
    let Value::String(text) = value else {
        return Err(at.refuse("$link must be a CID string"));
    };
    let cid = text
        .parse::<Cid>()
        .map_err(|_| at.refuse("$link is not a CID"))?;
    if cid.version() != Version::V1 || cid.to_string() != *text {
        return Err(at.refuse("$link must be a canonical CID string (CIDv1, base32)"));
    }
    Ok(cid)
}

/// The reference's detection: string `cid`, string `mimeType`, no `$type`.
fn is_legacy_blob(fields: &Map<String, Value>) -> bool {
    fields.get("cid").is_some_and(Value::is_string)
        && fields.get("mimeType").is_some_and(Value::is_string)
}

fn blob(fields: &Map<String, Value>, at: &At) -> Result<Ipld, DataModelError> {
    if fields
        .keys()
        .any(|k| !matches!(k.as_str(), "$type" | "ref" | "mimeType" | "size"))
    {
        return Err(at.refuse("a blob has only $type, ref, mimeType and size"));
    }
    let reference = fields
        .get("ref")
        .and_then(Value::as_object)
        .filter(|r| r.len() == 1)
        .and_then(|r| r.get("$link"))
        .ok_or_else(|| at.refuse("a blob's ref must be a $link"))?;
    let ref_at = at.key("ref");
    let cid = link_of(reference, &ref_at)?;
    if cid.codec() != RAW || cid.hash().code() != SHA2_256 || cid.hash().size() != 32 {
        return Err(at.refuse("a blob's ref must be a raw sha-256 CIDv1"));
    }
    let mime = match fields.get("mimeType") {
        Some(Value::String(m)) if !m.is_empty() => m,
        _ => return Err(at.refuse("a blob needs a non-empty mimeType")),
    };
    // Through `number`, so a size of `10000.0` is the integer it is, as any
    // other integral number is.
    let size = match fields.get("size") {
        Some(Value::Number(n)) => match number(n, &at.key("size"))? {
            Ipld::Integer(i) if i >= 0 => i,
            _ => return Err(at.refuse("a blob's size must be a non-negative integer")),
        },
        _ => return Err(at.refuse("a blob's size must be a non-negative integer")),
    };
    Ok(Ipld::Map(BTreeMap::from([
        ("$type".to_string(), Ipld::String("blob".into())),
        ("ref".to_string(), Ipld::Link(cid)),
        ("mimeType".to_string(), Ipld::String(mime.clone())),
        ("size".to_string(), Ipld::Integer(size)),
    ])))
}

/// A stored record as the wire sees it.
///
/// Integers outside i64/u64 and non-finite floats, possible only in records
/// committed before these rules, read back as null.
pub fn to_json(ipld: &Ipld) -> Value {
    match ipld {
        Ipld::Null => Value::Null,
        Ipld::Bool(b) => Value::Bool(*b),
        Ipld::Integer(i) => i64::try_from(*i)
            .ok()
            .map(Number::from)
            .or_else(|| u64::try_from(*i).ok().map(Number::from))
            .map(Value::Number)
            .unwrap_or(Value::Null),
        // Only records committed before these rules hold one.
        Ipld::Float(f) => Number::from_f64(*f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        Ipld::String(s) => Value::String(s.clone()),
        Ipld::Bytes(b) => serde_json::json!({ "$bytes": STANDARD_NO_PAD.encode(b) }),
        Ipld::List(items) => Value::Array(items.iter().map(to_json).collect()),
        Ipld::Map(fields) => Value::Object(
            fields
                .iter()
                .map(|(name, field)| (name.clone(), to_json(field)))
                .collect(),
        ),
        Ipld::Link(cid) => serde_json::json!({ "$link": cid.to_string() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RAW_CID: &str = "bafkreiccldh766hwcnuxnf2wh6jgzepf2nlu2lvcllt63eww5p6chi4ity";
    const CBOR_CID: &str = "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a";
    const V0_CID: &str = "QmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR";

    fn blob_with(reference: Value) -> Value {
        json!({"$type": "blob", "ref": reference, "mimeType": "image/png", "size": 4})
    }

    fn cid_with_digest(len: usize) -> String {
        let mh =
            ipld_core::cid::multihash::Multihash::<64>::wrap(SHA2_256, &vec![7u8; len]).unwrap();
        Cid::new_v1(RAW, mh).to_string()
    }

    fn err(path: &str, reason: &str) -> Result<Value, String> {
        Err(format!("{path}: {reason}"))
    }

    #[test]
    fn the_data_model_table() {
        let long = "k".repeat(100);
        let echoed = format!("{}…", "k".repeat(KEY_ECHO));
        let mut extra = blob_with(json!({"$link": RAW_CID}));
        extra["extra"] = json!(1);
        let mut no_mime = blob_with(json!({"$link": RAW_CID}));
        no_mime.as_object_mut().unwrap().remove("mimeType");
        let mut no_size = blob_with(json!({"$link": RAW_CID}));
        no_size.as_object_mut().unwrap().remove("size");
        let mut float_size = blob_with(json!({"$link": RAW_CID}));
        float_size["size"] = json!(10000.0);
        let mut want_size = blob_with(json!({"$link": RAW_CID}));
        want_size["size"] = json!(10000);

        let mut deep = json!({"x": 1.5});
        for _ in 0..19 {
            deep = json!({"a": deep});
        }
        let deep_path = format!("record/…/{}x", "a/".repeat(14));

        let rows: Vec<(Value, Result<Value, String>)> = vec![
            // numbers
            (json!(-9.223_372_036_854_776e18), Ok(json!(i64::MIN))),
            (json!(1e3), Ok(json!(1000))),
            (json!(123.0), Ok(json!(123))),
            (json!(-0.0), Ok(json!(0))),
            (
                json!(1e19),
                err("record", "integers are limited to 64-bit signed"),
            ),
            (
                json!(-1e19),
                err("record", "integers are limited to 64-bit signed"),
            ),
            (
                json!(9223372036854775807.0),
                err("record", "integers are limited to 64-bit signed"),
            ),
            (
                json!(u64::MAX),
                err("record", "integers are limited to 64-bit signed"),
            ),
            (json!(1.5), err("record", "floats are not allowed")),
            // links and bytes
            (
                json!({"a": [{"b": {"$link": CBOR_CID}}, {"c": {"$bytes": "AQID"}}]}),
                Ok(json!({"a": [{"b": {"$link": CBOR_CID}}, {"c": {"$bytes": "AQID"}}]})),
            ),
            (
                json!({"$link": RAW_CID.to_uppercase()}),
                err(
                    "record",
                    "$link must be a canonical CID string (CIDv1, base32)",
                ),
            ),
            // Not a CID string at all (it fails to parse), unlike the canonical-form refusals.
            (
                json!({"$link": format!("z{}", "2".repeat(40))}),
                err("record", "$link is not a CID"),
            ),
            (
                json!({"$link": V0_CID}),
                err(
                    "record",
                    "$link must be a canonical CID string (CIDv1, base32)",
                ),
            ),
            (json!({"$bytes": "AQI="}), Ok(json!({"$bytes": "AQI"}))),
            (json!({"$bytes": "AQI"}), Ok(json!({"$bytes": "AQI"}))),
            (
                json!({"$bytes": "AQI=="}),
                err("record", "$bytes is not base64"),
            ),
            // blobs
            (
                blob_with(json!({"$link": RAW_CID})),
                Ok(blob_with(json!({"$link": RAW_CID}))),
            ),
            (
                blob_with(json!({"$link": CBOR_CID})),
                err("record", "a blob's ref must be a raw sha-256 CIDv1"),
            ),
            (
                blob_with(json!(RAW_CID)),
                err("record", "a blob's ref must be a $link"),
            ),
            (
                blob_with(json!({"$link": cid_with_digest(20)})),
                err("record", "a blob's ref must be a raw sha-256 CIDv1"),
            ),
            (
                extra,
                err("record", "a blob has only $type, ref, mimeType and size"),
            ),
            (no_mime, err("record", "a blob needs a non-empty mimeType")),
            (
                no_size,
                err("record", "a blob's size must be a non-negative integer"),
            ),
            (float_size, Ok(want_size)),
            (
                json!({"cid": RAW_CID, "mimeType": "image/png"}),
                err("record", "legacy blob refs are not allowed"),
            ),
            // $type
            (
                json!({"x": {"$type": ""}}),
                err("record/x", "$type must be a non-empty string"),
            ),
            (
                json!({"x": {"$type": 1}}),
                err("record/x", "$type must be a non-empty string"),
            ),
            (
                json!({"x": {"$type": "com.example.y"}}),
                Ok(json!({"x": {"$type": "com.example.y"}})),
            ),
            // error paths
            (deep, err(&deep_path, "floats are not allowed")),
            (
                json!({ long.clone(): {"x": 1.5} }),
                err(&format!("record/{echoed}/x"), "floats are not allowed"),
            ),
            (
                json!({"a/b~c": [0, 1.5]}),
                err("record/a~1b~0c/1", "floats are not allowed"),
            ),
        ];
        for (input, expected) in rows {
            let got = from_json(&input)
                .map(|i| to_json(&i))
                .map_err(|e| e.to_string());
            assert_eq!(got, expected, "input {input}");
        }
    }

    #[test]
    fn a_record_must_be_an_object() {
        let e = record_from_json(&json!([1])).unwrap_err();
        assert_eq!(e.to_string(), "record: must be an object");
    }
}
