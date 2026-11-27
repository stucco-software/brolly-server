//! The validator (stage 4a, H4; Decision D): a record's normalised JSON
//! against its schema. Unexpected fields are ignored, as the lexicon
//! evolution rules require; only declared properties are descended, so a
//! path is built from schema names and indices, never from a client's keys.

use serde_json::{Map, Value};
use unicode_segmentation::UnicodeSegmentation;

use super::formats;
use super::registry::{Registry, resolve};

/// How deep the walk may go through nesting and refs. Recursive lexicons
/// exist; this bounds the walk whatever the record.
const MAX_DEPTH: usize = 64;

type Check = Result<(), String>;

fn is_link(v: &Value) -> bool {
    v.as_object()
        .is_some_and(|o| o.len() == 1 && o.get("$link").is_some_and(Value::is_string))
}

fn bytes_b64(v: &Value) -> Option<&str> {
    v.as_object()
        .filter(|o| o.len() == 1)
        .and_then(|o| o.get("$bytes"))
        .and_then(Value::as_str)
}

fn is_blob(v: &Value) -> bool {
    v.get("$type").and_then(Value::as_str) == Some("blob")
}

/// An object that is not one of the data model's special forms.
fn plain_object(v: &Value) -> Option<&Map<String, Value>> {
    v.as_object()
        .filter(|_| !is_link(v) && bytes_b64(v).is_none())
}

fn uint(schema: &Value, field: &str) -> Option<u64> {
    schema.get(field).and_then(Value::as_u64)
}

fn names<'a>(schema: &'a Value, field: &str) -> Vec<&'a str> {
    schema
        .get(field)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

impl Registry {
    pub(crate) fn check(
        &self,
        base: &str,
        schema: &Value,
        value: &Value,
        path: &str,
        depth: usize,
    ) -> Check {
        if depth > MAX_DEPTH {
            return Err(format!("{path} is nested too deeply"));
        }
        match schema.get("type").and_then(Value::as_str).unwrap_or("") {
            "null" if value.is_null() => Ok(()),
            "null" => Err(format!("{path} must be null")),
            "boolean" => boolean(schema, value, path),
            "integer" => integer(schema, value, path),
            "string" => string(schema, value, path),
            "bytes" => bytes(schema, value, path),
            "cid-link" if is_link(value) => Ok(()),
            "cid-link" => Err(format!("{path} must be a CID")),
            "blob" => blob(schema, value, path),
            "unknown" => match plain_object(value) {
                Some(_) if !is_blob(value) => Ok(()),
                _ => Err(format!("{path} must be an object")),
            },
            "array" => self.array(base, schema, value, path, depth),
            "object" => self.object(base, schema, value, path, depth),
            "ref" => self.reference(base, schema, value, path, depth),
            "union" => self.union(base, schema, value, path, depth),
            // A token is a value reached through a `ref` (`reference`
            // handles it); written inline as a field it can hold nothing.
            "token" => Err(format!("{path}: a token is a value, not a field")),
            other => Err(format!("{path}: the lexicon has no rule for {other:?}")),
        }
    }

    fn object(&self, base: &str, schema: &Value, value: &Value, path: &str, depth: usize) -> Check {
        let Some(fields) = plain_object(value) else {
            return Err(format!("{path} must be an object"));
        };
        for key in names(schema, "required") {
            if !fields.contains_key(key) {
                return Err(format!("{path} must have the property \"{key}\""));
            }
        }
        let nullable = names(schema, "nullable");
        let Some(props) = schema.get("properties").and_then(Value::as_object) else {
            return Ok(());
        };
        for (key, prop) in props {
            match fields.get(key) {
                None => {}
                Some(Value::Null) if nullable.contains(&key.as_str()) => {}
                Some(v) => self.check(base, prop, v, &format!("{path}/{key}"), depth + 1)?,
            }
        }
        Ok(())
    }

    fn array(&self, base: &str, schema: &Value, value: &Value, path: &str, depth: usize) -> Check {
        let Some(items) = value.as_array() else {
            return Err(format!("{path} must be an array"));
        };
        let len = items.len() as u64;
        if let Some(max) = uint(schema, "maxLength")
            && len > max
        {
            return Err(format!("{path} must not have more than {max} elements"));
        }
        if let Some(min) = uint(schema, "minLength")
            && len < min
        {
            return Err(format!("{path} must not have fewer than {min} elements"));
        }
        let Some(item_schema) = schema.get("items") else {
            return Ok(());
        };
        for (i, item) in items.iter().enumerate() {
            self.check(base, item_schema, item, &format!("{path}/{i}"), depth + 1)?;
        }
        Ok(())
    }

    fn reference(
        &self,
        base: &str,
        schema: &Value,
        value: &Value,
        path: &str,
        depth: usize,
    ) -> Check {
        let r = schema.get("ref").and_then(Value::as_str).unwrap_or("");
        let (nsid, name) = resolve(base, r);
        let Some(def) = self.def(nsid, name) else {
            return Err(format!(
                "{path}: the lexicon refers to {nsid}#{name}, which is not loaded"
            ));
        };
        if def.get("type").and_then(Value::as_str) == Some("token") {
            let token = format!("{nsid}#{name}");
            return match value.as_str() {
                Some(s) if s == token => Ok(()),
                _ => Err(format!("{path} must be {token}")),
            };
        }
        self.check(nsid, def, value, path, depth + 1)
    }

    fn union(&self, base: &str, schema: &Value, value: &Value, path: &str, depth: usize) -> Check {
        let Some(t) = plain_object(value)
            .and_then(|o| o.get("$type"))
            .and_then(Value::as_str)
        else {
            return Err(format!(
                "{path} must be an object which includes the \"$type\" property"
            ));
        };
        let want = if t.contains('#') {
            t.to_string()
        } else {
            format!("{t}#main")
        };
        let refs = names(schema, "refs");
        for r in &refs {
            let (nsid, name) = resolve(base, r);
            if format!("{nsid}#{name}") == want {
                let Some(def) = self.def(nsid, name) else {
                    return Err(format!(
                        "{path}: the lexicon refers to {want}, which is not loaded"
                    ));
                };
                return self.check(nsid, def, value, path, depth + 1);
            }
        }
        if schema.get("closed").and_then(Value::as_bool) == Some(true) {
            let all: Vec<String> = refs
                .iter()
                .map(|r| {
                    let (nsid, name) = resolve(base, r);
                    format!("{nsid}#{name}")
                })
                .collect();
            return Err(format!("{path} $type must be one of {}", all.join(", ")));
        }
        // An open union accepts a type it does not know, unvalidated.
        Ok(())
    }
}

fn boolean(schema: &Value, value: &Value, path: &str) -> Check {
    let Some(b) = value.as_bool() else {
        return Err(format!("{path} must be a boolean"));
    };
    match schema.get("const").and_then(Value::as_bool) {
        Some(c) if c != b => Err(format!("{path} must be {c}")),
        _ => Ok(()),
    }
}

fn integer(schema: &Value, value: &Value, path: &str) -> Check {
    let Some(n) = value.as_i64() else {
        return Err(format!("{path} must be an integer"));
    };
    if let Some(c) = schema.get("const").and_then(Value::as_i64)
        && c != n
    {
        return Err(format!("{path} must be {c}"));
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array)
        && !allowed.iter().any(|a| a.as_i64() == Some(n))
    {
        let list: Vec<String> = allowed.iter().map(Value::to_string).collect();
        return Err(format!("{path} must be one of ({})", list.join("|")));
    }
    if let Some(max) = schema.get("maximum").and_then(Value::as_i64)
        && n > max
    {
        return Err(format!("{path} can not be greater than {max}"));
    }
    if let Some(min) = schema.get("minimum").and_then(Value::as_i64)
        && n < min
    {
        return Err(format!("{path} can not be less than {min}"));
    }
    Ok(())
}

fn string(schema: &Value, value: &Value, path: &str) -> Check {
    let Some(s) = value.as_str() else {
        return Err(format!("{path} must be a string"));
    };
    if let Some(c) = schema.get("const").and_then(Value::as_str)
        && c != s
    {
        return Err(format!("{path} must be {c}"));
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array)
        && !allowed.iter().any(|a| a.as_str() == Some(s))
    {
        let list: Vec<&str> = allowed.iter().filter_map(Value::as_str).collect();
        return Err(format!("{path} must be one of ({})", list.join("|")));
    }
    let bytes = s.len() as u64;
    if let Some(max) = uint(schema, "maxLength")
        && bytes > max
    {
        return Err(format!("{path} must not be longer than {max} characters"));
    }
    if let Some(min) = uint(schema, "minLength")
        && bytes < min
    {
        return Err(format!("{path} must not be shorter than {min} characters"));
    }
    // A string has no more graphemes than bytes, so a short one is never
    // counted for a maximum.
    let mut counted = None;
    let mut graphemes = || *counted.get_or_insert_with(|| s.graphemes(true).count() as u64);
    if let Some(max) = uint(schema, "maxGraphemes")
        && bytes > max
        && graphemes() > max
    {
        return Err(format!("{path} must not be longer than {max} graphemes"));
    }
    if let Some(min) = uint(schema, "minGraphemes")
        && graphemes() < min
    {
        return Err(format!("{path} must not be shorter than {min} graphemes"));
    }
    if let Some(format) = schema.get("format").and_then(Value::as_str)
        && !formats::check(format, s)
    {
        return Err(format!("{path} must be a valid {format}"));
    }
    Ok(())
}

fn bytes(schema: &Value, value: &Value, path: &str) -> Check {
    let Some(b64) = bytes_b64(value) else {
        return Err(format!("{path} must be a byte array"));
    };
    // The data model has already decoded it once; its length follows from
    // the unpadded length without decoding again.
    let len = (b64.trim_end_matches('=').len() * 3 / 4) as u64;
    if let Some(max) = uint(schema, "maxLength")
        && len > max
    {
        return Err(format!("{path} must not be larger than {max} bytes"));
    }
    if let Some(min) = uint(schema, "minLength")
        && len < min
    {
        return Err(format!("{path} must not be smaller than {min} bytes"));
    }
    Ok(())
}

/// `accept` as the lexicon defines it: exact types, `type/*`, and `*/*`.
/// Nothing else is a glob.
fn accepts(pattern: &str, mime: &str) -> bool {
    if pattern == "*/*" {
        return true;
    }
    match pattern.strip_suffix("/*") {
        Some(top) => mime.split_once('/').is_some_and(|(t, _)| t == top),
        None => pattern == mime,
    }
}

fn blob(schema: &Value, value: &Value, path: &str) -> Check {
    if !is_blob(value) {
        return Err(format!("{path} must be a blob ref"));
    }
    let mime = value.get("mimeType").and_then(Value::as_str).unwrap_or("");
    let size = value
        .get("size")
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX);
    if let Some(accept) = schema.get("accept").and_then(Value::as_array) {
        let list: Vec<&str> = accept.iter().filter_map(Value::as_str).collect();
        if !list.iter().any(|p| accepts(p, mime)) {
            return Err(format!(
                "{path} mimeType {mime} is not accepted ({})",
                list.join(", ")
            ));
        }
    }
    if let Some(max) = uint(schema, "maxSize")
        && size > max
    {
        return Err(format!("{path} is {size} bytes, over maxSize {max}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_is_exact_or_a_whole_top_level_type() {
        assert!(accepts("*/*", "video/mp4"));
        assert!(accepts("image/*", "image/png"));
        assert!(!accepts("image/*", "imagey/png"));
        assert!(accepts("image/png", "image/png"));
        assert!(!accepts("image/pn*", "image/png"));
    }

    #[test]
    fn a_byte_length_follows_from_padded_and_unpadded_base64() {
        for (b64, len) in [
            ("", 0),
            ("AQ", 1),
            ("AQ==", 1),
            ("AQI", 2),
            ("AQID", 3),
            ("AQIDBA", 4),
        ] {
            assert_eq!((b64.trim_end_matches('=').len() * 3 / 4), len, "{b64}");
        }
    }
}
