//! String formats (stage 4a, H4). Identifier formats accept the most
//! expansive syntax; the interop syntax vectors are the bar.
//!
//! atrium's identifier types (`Did`, `Handle`, `Nsid`, `Tid`, `RecordKey`)
//! agree with the vectors and are reused. Three formats leave atrium:
//! `datetime` (atrium's `Datetime` refuses every negative offset but
//! `-0X:00`-style ones, so a `-10:00` `createdAt` would be refused, and it
//! accepts year-zero instants the reference refuses), `language` (`langtag`
//! accepts primary subtags like `jaja` and `JA` the reference refuses), and
//! `uri`/`at-uri`, which follow the reference's own patterns
//! (`@atproto/syntax`, `@atproto/lexicon`'s `formats.ts`). `cid` is checked
//! for syntax only, as the reference's lexicon does.

use std::sync::LazyLock;

use atrium_api::types::string::{Did, Handle, Language, Nsid, RecordKey, Tid};
use regex::Regex;

/// RFC 3339 ∩ ISO 8601 as the data model has it: uppercase `T`, seconds
/// required, any number of fractional digits, `Z` or a numeric offset.
static DATETIME: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"^[0-9]{4}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-6][0-9]:[0-6][0-9](\.[0-9]{1,20})?(Z|[+-][0-2][0-9]:[0-5][0-9])$",
    )
    .ok()
});

/// 0000-01-01T00:00:00Z: the reference refuses an instant before year zero.
const YEAR_ZERO: i64 = -62_167_219_200;

/// A BCP 47 primary language subtag as the reference reads it: two or three
/// lowercase letters, or the `i`/`x` singletons.
static LANGUAGE_PRIMARY: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^(i|x|X|[a-z]{2,3})(-|$)").ok());

/// A URI scheme (RFC 3986: a letter, then letters, digits, `+`, `.`, `-`)
/// and a non-empty, whitespace-free rest.
static URI: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$").ok());

/// The reference's AT-URI pattern: authority, optional collection,
/// optional rkey, optional `#/…` fragment.
static AT_URI: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"^at://([a-zA-Z0-9._:%-]+)(/([a-zA-Z0-9.-]+)(/([a-zA-Z0-9._~:@!$&%')(*+,;=-]+))?)?(#(/[a-zA-Z0-9._~:@!$&%')(*+,;=\-\[\]/\\]*))?$",
    )
    .ok()
});

fn matches(re: &LazyLock<Option<Regex>>, s: &str) -> bool {
    re.as_ref().is_some_and(|re| re.is_match(s))
}

/// Whether `s` is a valid `format`. A format this pin does not know is
/// accepted: the field is still a string, and the evolution rules let a
/// newer lexicon add one.
pub fn check(format: &str, s: &str) -> bool {
    match format {
        "at-identifier" => at_identifier(s),
        "at-uri" => at_uri(s),
        "cid" => cid(s),
        "datetime" => datetime(s),
        "did" => Did::new(s.to_string()).is_ok(),
        "handle" => Handle::new(s.to_string()).is_ok(),
        "language" => matches(&LANGUAGE_PRIMARY, s) && Language::new(s.to_string()).is_ok(),
        "nsid" => Nsid::new(s.to_string()).is_ok(),
        "record-key" => RecordKey::new(s.to_string()).is_ok(),
        "tid" => Tid::new(s.to_string()).is_ok(),
        "uri" => s.len() <= 8192 && matches(&URI, s),
        _ => true,
    }
}

fn at_identifier(s: &str) -> bool {
    if s.starts_with("did:") {
        Did::new(s.to_string()).is_ok()
    } else {
        Handle::new(s.to_string()).is_ok()
    }
}

fn at_uri(s: &str) -> bool {
    if s.len() > 8192 {
        return false;
    }
    let Some(caps) = AT_URI.as_ref().and_then(|re| re.captures(s)) else {
        return false;
    };
    let authority_ok = caps.get(1).is_some_and(|a| at_identifier(a.as_str()));
    let collection_ok = caps
        .get(3)
        .is_none_or(|c| Nsid::new(c.as_str().to_string()).is_ok());
    let rkey_ok = caps
        .get(5)
        .is_none_or(|r| RecordKey::new(r.as_str().to_string()).is_ok());
    authority_ok && collection_ok && rkey_ok
}

/// Syntax only, as the reference's lexicon checks it; a CIDv0 (`Qmb…`) is
/// not a CID string the network writes.
fn cid(s: &str) -> bool {
    (8..=256).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '=')
        && !s.starts_with("Qmb")
}

fn datetime(s: &str) -> bool {
    s.len() <= 64
        && !s.ends_with("-00:00")
        && matches(&DATETIME, s)
        // The calendar (month 13, hour 25 pass the pattern) and year zero.
        && time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
            .is_ok_and(|d| d.unix_timestamp() >= YEAR_ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pattern_compiles() {
        for re in [&DATETIME, &LANGUAGE_PRIMARY, &URI, &AT_URI] {
            assert!(re.is_some());
        }
    }

    #[test]
    fn a_negative_offset_is_a_datetime() {
        // Not in the interop vectors; atrium's `Datetime` refuses it.
        assert!(datetime("1985-04-12T23:20:50.123-10:00"));
        assert!(datetime("2026-11-27T00:00:00.123456789012Z"));
    }
}
