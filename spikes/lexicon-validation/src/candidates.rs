use serde_json::Value;

use crate::{Candidate, Verdict, key_of, key_ok};

pub fn load(which: &str, docs: &[Value]) -> anyhow::Result<Box<dyn Candidate>> {
    match which {
        "atproto-lexicon" => Ok(Box::new(AtprotoLexicon::new(docs)?)),
        // DIAGNOSTIC ONLY, not the measurement: the same crate fed our
        // documents with every `"type": "null"` property removed in memory,
        // because it refuses the `null` type and so cannot load
        // `com.example.corpus.thing`. Shows how it does on everything else.
        "atproto-lexicon:diag-no-null" => {
            let stripped: Vec<Value> = docs.iter().cloned().map(strip_null_props).collect();
            Ok(Box::new(AtprotoLexicon::new(&stripped)?))
        }
        "proto-blue-lexicon" => Ok(Box::new(ProtoBlueLexicon::new(docs)?)),
        // DIAGNOSTIC ONLY, as above: this crate has no `null` type either.
        "proto-blue-lexicon:diag-no-null" => {
            let stripped: Vec<Value> = docs.iter().cloned().map(strip_null_props).collect();
            Ok(Box::new(ProtoBlueLexicon::new(&stripped)?))
        }
        other => anyhow::bail!("no candidate named {other}"),
    }
}

/// Remove every object property whose schema is `{"type": "null"}`.
fn strip_null_props(mut v: Value) -> Value {
    fn walk(v: &mut Value) {
        match v {
            Value::Object(map) => {
                if let Some(Value::Object(props)) = map.get_mut("properties") {
                    props.retain(|_, p| p["type"] != "null");
                }
                map.values_mut().for_each(walk);
            }
            Value::Array(items) => items.iter_mut().for_each(walk),
            _ => {}
        }
    }
    walk(&mut v);
    v
}

/// Candidate A: `atproto-lexicon` 0.14.
///
/// Used: `validation::SchemaFile::from_value` (a lexicon doc from a
/// `serde_json::Value`), `validation::BaseCatalog::{new, add_schema,
/// get_schema}` (an in-memory catalog of our documents — no resolver, no
/// network), and `validation::validate_record(nsid, &Value, &catalog,
/// ValidateFlags::empty())`, whose error is `DataValidationError`
/// (`Display` carries the JSON path where it has one).
pub struct AtprotoLexicon {
    catalog: atproto_lexicon::validation::BaseCatalog,
    docs: Vec<Value>,
}

impl AtprotoLexicon {
    pub fn new(docs: &[Value]) -> anyhow::Result<Self> {
        use atproto_lexicon::validation::{BaseCatalog, SchemaFile};
        let mut catalog = BaseCatalog::new();
        let mut refused = 0;
        for doc in docs {
            let id = doc["id"].as_str().unwrap_or("?");
            // A document the crate cannot parse is not in its catalog, so its
            // records come back Unknown — what the server would do with it.
            match SchemaFile::from_value(doc.clone()) {
                Ok(file) => catalog.add_schema(file),
                Err(e) => {
                    refused += 1;
                    eprintln!("LOAD-REFUSED {id}: {e}");
                }
            }
        }
        eprintln!(
            "loaded {} of {} documents",
            docs.len() - refused,
            docs.len()
        );
        Ok(Self {
            catalog,
            docs: docs.to_vec(),
        })
    }
}

impl Candidate for AtprotoLexicon {
    fn name(&self) -> &'static str {
        "atproto-lexicon"
    }

    fn check(&self, collection: &str, rkey: &str, record: &Value) -> Verdict {
        use atproto_lexicon::validation::{ValidateFlags, validate_record};
        if self.catalog.get_schema(collection).is_none() {
            return Verdict::Unknown;
        }
        if let Some(key) = key_of(&self.docs, collection)
            && !key_ok(&key, rkey)
        {
            return Verdict::Invalid(format!("(harness) rkey {rkey:?} is not a valid {key}"));
        }
        match validate_record(collection, record, &self.catalog, ValidateFlags::empty()) {
            Ok(()) => Verdict::Valid,
            Err(e) => Verdict::Invalid(e.to_string()),
        }
    }
}

/// Candidate B: `proto-blue-lexicon` 0.3.
///
/// Used: `serde_json::from_value::<proto_blue_lexicon::LexiconDoc>` (a
/// lexicon doc from a `serde_json::Value`), `Lexicons::{new, add, get,
/// get_def}` (an in-memory registry of our documents; `get_def` returns the
/// def with refs made absolute), and `validate_record(&lexicons,
/// &LexRecord, &LexValue)`, whose error is `ValidationError` (`InvalidValue
/// { path, message }`, or `DefNotFound` for an unresolvable ref). The
/// record is converted with the family's own `proto_blue_lex_json::
/// json_to_lex_with(.., LexParseOptions::strict())` — strict, so a float or
/// malformed `$link`/`$bytes` is an error rather than silently coerced.
pub struct ProtoBlueLexicon {
    lexicons: proto_blue_lexicon::Lexicons,
    docs: Vec<Value>,
}

impl ProtoBlueLexicon {
    pub fn new(docs: &[Value]) -> anyhow::Result<Self> {
        use proto_blue_lexicon::{LexiconDoc, Lexicons};
        let mut lexicons = Lexicons::new();
        let mut refused = 0;
        for doc in docs {
            let id = doc["id"].as_str().unwrap_or("?");
            // As for candidate A: a refused document is not in the registry.
            let added = serde_json::from_value::<LexiconDoc>(doc.clone())
                .map_err(|e| e.to_string())
                .and_then(|d| lexicons.add(d).map_err(|e| e.to_string()));
            if let Err(e) = added {
                refused += 1;
                eprintln!("LOAD-REFUSED {id}: {e}");
            }
        }
        eprintln!(
            "loaded {} of {} documents",
            docs.len() - refused,
            docs.len()
        );
        Ok(Self {
            lexicons,
            docs: docs.to_vec(),
        })
    }
}

impl Candidate for ProtoBlueLexicon {
    fn name(&self) -> &'static str {
        "proto-blue-lexicon"
    }

    fn check(&self, collection: &str, rkey: &str, record: &Value) -> Verdict {
        use proto_blue_lex_json::{LexParseOptions, json_to_lex_with};
        use proto_blue_lexicon::{LexUserType, validate_record};
        if self.lexicons.get(collection).is_none() {
            return Verdict::Unknown;
        }
        if let Some(key) = key_of(&self.docs, collection)
            && !key_ok(&key, rkey)
        {
            return Verdict::Invalid(format!("(harness) rkey {rkey:?} is not a valid {key}"));
        }
        let Some(LexUserType::Record(def)) = self.lexicons.get_def(collection) else {
            return Verdict::Invalid(format!("(harness) {collection}#main is not a record"));
        };
        let value = match json_to_lex_with(record, LexParseOptions::strict()) {
            Ok(v) => v,
            Err(e) => return Verdict::Invalid(format!("(lex-json) {e}")),
        };
        match validate_record(&self.lexicons, def, &value) {
            Ok(()) => Verdict::Valid,
            Err(e) => Verdict::Invalid(e.to_string()),
        }
    }
}
