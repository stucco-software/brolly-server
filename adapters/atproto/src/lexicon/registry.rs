//! Loading lexicon documents and resolving references between them (H3).

use std::collections::{BTreeMap, BTreeSet};

use atrium_api::types::string::{Nsid, Tid};
use serde_json::{Map, Value};

/// Why a set of lexicon documents did not load. The message names the
/// document and the def.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadError(pub String);

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "lexicons: {}", self.0)
    }
}

impl std::error::Error for LoadError {}

fn fail(what: impl Into<String>) -> LoadError {
    LoadError(what.into())
}

/// Def types that are a document's primary type, and so may only be `main`.
const PRIMARY: [&str; 5] = [
    "record",
    "query",
    "procedure",
    "subscription",
    "permission-set",
];
/// Field types that may not stand as a def of their own.
const FIELD_ONLY: [&str; 3] = ["ref", "union", "unknown"];
/// The types a record's schema may contain, wherever it nests.
const FIELD_TYPES: [&str; 13] = [
    "null", "boolean", "integer", "string", "bytes", "cid-link", "blob", "array", "object", "ref",
    "union", "unknown", "token",
];

/// A set of loaded lexicons: each document's `defs`, by NSID.
#[derive(Debug)]
pub struct Registry {
    docs: BTreeMap<String, Map<String, Value>>,
}

/// `r` as `(nsid, def)`, relative to the document `base` it appears in:
/// `#def` is local, `nsid#def` is remote, a bare `nsid` is its `main`.
pub(crate) fn resolve<'a>(base: &'a str, r: &'a str) -> (&'a str, &'a str) {
    if let Some(def) = r.strip_prefix('#') {
        return (base, def);
    }
    match r.split_once('#') {
        Some((nsid, def)) => (nsid, def),
        None => (r, "main"),
    }
}

/// Every `.json` file in an embedded tree, parsed.
pub(crate) fn documents(dir: &include_dir::Dir<'_>) -> Result<Vec<Value>, LoadError> {
    let mut out = Vec::new();
    let mut stack = vec![dir];
    while let Some(d) = stack.pop() {
        stack.extend(d.dirs());
        for file in d.files() {
            if file.path().extension().is_some_and(|e| e == "json") {
                let doc = serde_json::from_slice(file.contents())
                    .map_err(|e| fail(format!("{}: {e}", file.path().display())))?;
                out.push(doc);
            }
        }
    }
    Ok(out)
}

impl Registry {
    /// Load `docs`, checking each document's structure and that every ref
    /// reachable from a record resolves.
    pub fn from_docs(docs: Vec<Value>) -> Result<Self, LoadError> {
        let mut map = BTreeMap::new();
        for doc in docs {
            let (id, defs) = check_doc(doc)?;
            if map.contains_key(&id) {
                return Err(fail(format!("{id}: defined twice")));
            }
            map.insert(id, defs);
        }
        let registry = Registry { docs: map };
        let mut seen = BTreeSet::new();
        for (id, defs) in &registry.docs {
            if let Some(main) = defs.get("main").filter(|m| type_of(m) == Some("record")) {
                registry.walk(id, main, &mut seen)?;
            }
        }
        Ok(registry)
    }

    /// The def `nsid#name`, if loaded.
    pub(crate) fn def(&self, nsid: &str, name: &str) -> Option<&Value> {
        self.docs.get(nsid)?.get(name)
    }

    /// Whether `nsid` names a loaded document at all.
    pub fn knows(&self, nsid: &str) -> bool {
        self.docs.contains_key(nsid)
    }

    /// Whether `nsid`'s `main` is a record lexicon.
    pub fn is_record(&self, nsid: &str) -> bool {
        self.record(nsid).is_some()
    }

    /// `nsid`'s `main` def, when it is a record.
    pub(crate) fn record(&self, nsid: &str) -> Option<&Value> {
        self.def(nsid, "main")
            .filter(|m| type_of(m) == Some("record"))
    }

    /// The closure walk: `schema` (in document `base`) and everything it
    /// reaches has a known type, and every ref resolves.
    fn walk(
        &self,
        base: &str,
        schema: &Value,
        seen: &mut BTreeSet<String>,
    ) -> Result<(), LoadError> {
        let ty = type_of(schema).ok_or_else(|| fail(format!("{base}: a schema has no type")))?;
        match ty {
            "record" => {
                let record = schema.get("record").unwrap_or(&Value::Null);
                self.walk(base, record, seen)
            }
            "object" => {
                if let Some(props) = schema.get("properties") {
                    let props = props
                        .as_object()
                        .ok_or_else(|| fail(format!("{base}: properties must be an object")))?;
                    for prop in props.values() {
                        self.walk(base, prop, seen)?;
                    }
                }
                for list in ["required", "nullable"] {
                    if let Some(names) = schema.get(list)
                        && !names
                            .as_array()
                            .is_some_and(|a| a.iter().all(Value::is_string))
                    {
                        return Err(fail(format!("{base}: {list} must be a list of names")));
                    }
                }
                Ok(())
            }
            "array" => {
                let items = schema
                    .get("items")
                    .ok_or_else(|| fail(format!("{base}: an array has no items")))?;
                self.walk(base, items, seen)
            }
            "ref" => {
                let r = schema
                    .get("ref")
                    .and_then(Value::as_str)
                    .ok_or_else(|| fail(format!("{base}: a ref has no ref")))?;
                self.follow(base, r, seen)
            }
            "union" => {
                let refs = schema
                    .get("refs")
                    .and_then(Value::as_array)
                    .ok_or_else(|| fail(format!("{base}: a union has no refs")))?;
                for r in refs {
                    let r = r
                        .as_str()
                        .ok_or_else(|| fail(format!("{base}: a union ref is not a string")))?;
                    self.follow(base, r, seen)?;
                }
                Ok(())
            }
            t if FIELD_TYPES.contains(&t) => Ok(()),
            other => Err(fail(format!("{base}: no such field type {other:?}"))),
        }
    }

    fn follow(&self, base: &str, r: &str, seen: &mut BTreeSet<String>) -> Result<(), LoadError> {
        let (nsid, name) = resolve(base, r);
        if !seen.insert(format!("{nsid}#{name}")) {
            return Ok(());
        }
        let def = self
            .def(nsid, name)
            .ok_or_else(|| fail(format!("{base}: {nsid}#{name} does not resolve")))?;
        self.walk(nsid, def, seen)
    }

    /// `record` — normalised JSON — against `collection`'s record lexicon,
    /// and `rkey` (when known) against its `key` (H4, H5).
    pub fn validate(
        &self,
        collection: &str,
        rkey: Option<&str>,
        record: &Value,
    ) -> Result<super::Status, String> {
        if !self.knows(collection) {
            return Ok(super::Status::Unknown);
        }
        let main = self
            .record(collection)
            .ok_or_else(|| format!("{collection} is not a record type"))?;
        if let Some(rkey) = rkey {
            self.check_key(collection, rkey)?;
        }
        let schema = main.get("record").unwrap_or(&Value::Null);
        self.check(collection, schema, record, "record", 0)?;
        Ok(super::Status::Valid)
    }

    /// `rkey` against `collection`'s record `key`. Unknown collections pass;
    /// the rkey's own grammar is checked where it is parsed.
    pub fn check_key(&self, collection: &str, rkey: &str) -> Result<(), String> {
        if !self.knows(collection) {
            return Ok(());
        }
        let key = self
            .record(collection)
            .ok_or_else(|| format!("{collection} is not a record type"))?
            .get("key")
            .and_then(Value::as_str)
            .unwrap_or("");
        let (ok, what) = match key {
            "any" => (true, "any"),
            "tid" => (Tid::new(rkey.to_string()).is_ok(), "a TID"),
            "nsid" => (Nsid::new(rkey.to_string()).is_ok(), "an NSID"),
            other => match other.strip_prefix("literal:") {
                Some(want) => (rkey == want, want),
                None => (false, other),
            },
        };
        if ok {
            Ok(())
        } else {
            Err(format!("record key {rkey} is not {what}"))
        }
    }
}

fn type_of(schema: &Value) -> Option<&str> {
    schema.get("type").and_then(Value::as_str)
}

/// One document's structure; its id and defs.
fn check_doc(doc: Value) -> Result<(String, Map<String, Value>), LoadError> {
    let Value::Object(mut doc) = doc else {
        return Err(fail("a document is not an object"));
    };
    if doc.get("lexicon").and_then(Value::as_u64) != Some(1) {
        return Err(fail(format!("{:?}: lexicon must be 1", doc.get("id"))));
    }
    let id = match doc.get("id").and_then(Value::as_str) {
        Some(id) if Nsid::new(id.to_string()).is_ok() => id.to_string(),
        other => return Err(fail(format!("{other:?}: id must be an NSID"))),
    };
    let Some(Value::Object(defs)) = doc.remove("defs") else {
        return Err(fail(format!("{id}: defs must be an object")));
    };
    for (name, def) in &defs {
        let ty = type_of(def).ok_or_else(|| fail(format!("{id}#{name}: no type")))?;
        if PRIMARY.contains(&ty) && name != "main" {
            return Err(fail(format!("{id}#{name}: a {ty} must be main")));
        }
        if FIELD_ONLY.contains(&ty) {
            return Err(fail(format!(
                "{id}#{name}: a {ty} cannot be a def of its own"
            )));
        }
        if ty == "record" {
            if def.get("key").and_then(Value::as_str).is_none() {
                return Err(fail(format!("{id}#{name}: a record needs a key")));
            }
            if def.get("record").and_then(type_of) != Some("object") {
                return Err(fail(format!(
                    "{id}#{name}: a record's record must be an object"
                )));
            }
        }
    }
    Ok((id, defs))
}
