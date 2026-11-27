//! Lexicons (stage 4a, H3, H4): the vendored documents, embedded and loaded
//! once, and the validator that holds a record to its collection's lexicon.
//!
//! Written, not adopted (Decision D): neither candidate crate passed the
//! corpus. The validator reads a record's **normalised** JSON — the
//! `data_model::to_json` of the IPLD that will be committed — so what is
//! validated is exactly what is signed (Decision F).

pub mod formats;
mod registry;
mod validate;

use std::sync::LazyLock;

pub use registry::{LoadError, Registry};

/// What validation said about a record that was not refused: the
/// `validationStatus` a write answers with (H6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Its lexicon is vendored and the record holds to it.
    Valid,
    /// Its collection has no vendored lexicon; accepted unvalidated.
    Unknown,
}

impl Status {
    /// The lexicon's `validationStatus` value.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Valid => "valid",
            Status::Unknown => "unknown",
        }
    }
}

static TREE: include_dir::Dir<'static> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/../../vendor/lexicons");

static VENDORED: LazyLock<Result<Registry, LoadError>> =
    LazyLock::new(|| Registry::from_docs(registry::documents(&TREE)?));

/// The vendored lexicons, parsed on first use. The server calls this at
/// startup, so a tree that does not load stops the boot rather than the
/// first write (Decision C).
pub fn vendored() -> Result<&'static Registry, LoadError> {
    VENDORED.as_ref().map_err(Clone::clone)
}
