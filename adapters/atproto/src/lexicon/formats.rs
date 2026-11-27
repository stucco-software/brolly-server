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
//! (`@atproto/syntax`, `@atproto/lexicon`'s `formats.ts`). `cid` is parsed,
//! as the reference's lexicon does (`isCidString` → `CID.parse`), and must be
//! a CIDv1; [`check_syntax`] keeps the syntax-only rule the interop syntax
//! vectors test, whose valid CIDs are made-up strings that do not parse.

use std::sync::LazyLock;

use atrium_api::types::string::{Did, Handle, Language, Nsid, RecordKey, Tid};
use regex::Regex;

/// RFC 3339 ∩ ISO 8601 as the data model has it: uppercase `T`, seconds
/// required, any number of fractional digits (the 64-character cap bounds
/// them), `Z` or a numeric offset.
static DATETIME: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"^[0-9]{4}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-6][0-9]:[0-6][0-9](\.[0-9]+)?(Z|[+-][0-2][0-9]:[0-5][0-9])$",
    )
    .ok()
});

/// 0000-01-01T00:00:00Z: the reference refuses an instant before year zero.
const YEAR_ZERO: i64 = -62_167_219_200;

/// 10000-01-01T00:00:00Z: JS `Date` (and so the reference) refuses an
/// instant whose UTC year has five digits, whatever its written offset.
const YEAR_10000: i64 = 253_402_300_800;

/// A BCP 47 primary language subtag as the reference reads it: two or three
/// lowercase letters, or the `i`/`x` singletons.
static LANGUAGE_PRIMARY: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^(i|x|X|[a-z]{2,3})(-|$)").ok());

/// The reference's URI pattern: a scheme (RFC 3986: a letter, then letters,
/// digits, `+`, `.`, `-`), an optional `//`, and a whitespace-free rest that
/// does not start with `/`.
static URI: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9+.-]*:(//)?[^\s/][^\s]*$").ok());

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

/// [`check`], except that `cid` is held to syntax alone: what the interop
/// syntax vectors test.
pub fn check_syntax(format: &str, s: &str) -> bool {
    match format {
        "cid" => cid_syntax(s),
        _ => check(format, s),
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

/// A CID the lexicon accepts: well-formed, at most 128 characters (the
/// reference's cap), parsed, and a CIDv1 — a CIDv0 is not a CID string the
/// network writes.
fn cid(s: &str) -> bool {
    cid_syntax(s)
        && s.len() <= 128
        && ipld_core::cid::Cid::try_from(s)
            .is_ok_and(|c| c.version() == ipld_core::cid::Version::V1)
}

/// CID syntax alone, as `@atproto/syntax`'s `ensureValidCidSyntax` has it.
fn cid_syntax(s: &str) -> bool {
    (8..=256).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '=')
        && !s.starts_with("Qmb")
}

fn datetime(s: &str) -> bool {
    s.len() <= 64
        && !s.ends_with("-00:00")
        && matches(&DATETIME, s)
        // Second 60: JS `Date` refuses a leap second, so the reference does.
        && s.get(17..19) != Some("60")
        // The calendar (month 13, hour 25 pass the pattern), year zero, and
        // a UTC year past 9999.
        && time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
            .is_ok_and(|d| (YEAR_ZERO..YEAR_10000).contains(&d.unix_timestamp()))
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

    #[test]
    fn fractional_seconds_are_unbounded_within_the_length_cap() {
        assert!(datetime("2026-11-27T00:00:00.123456789012345678901234567Z"));
    }

    #[test]
    fn a_leap_second_is_not_a_datetime() {
        // JS `Date` refuses second 60, so the reference does.
        assert!(!datetime("2016-12-31T23:59:60Z"));
        assert!(!datetime("2026-11-27T12:00:60.5+01:00"));
    }

    #[test]
    fn an_instant_past_year_9999_utc_is_not_a_datetime() {
        assert!(datetime("9999-12-31T23:59:59Z"));
        assert!(datetime("9999-12-31T23:59:59+01:00"));
        assert!(!datetime("9999-12-31T23:59:59-01:00"));
    }

    #[test]
    fn a_uri_needs_something_after_its_scheme_and_slashes() {
        assert!(check("uri", "https://example.com/x"));
        assert!(check("uri", "mailto:a@example.com"));
        assert!(!check("uri", "https:///x"));
        assert!(!check("uri", "file:/etc/passwd"));
        assert!(!check("uri", "a:/"));
    }

    #[test]
    fn a_cid_must_parse_as_a_cidv1() {
        assert!(check(
            "cid",
            "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a"
        ));
        assert!(!check("cid", "aaaaaaaa"));
        assert!(!check("cid", "bafyreiZZZZZZZZZZ"));
        // A CIDv0 that does not start `Qmb`: it parses, but is not v1.
        assert!(!check(
            "cid",
            "QmWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR"
        ));
        // Syntax alone still admits them.
        assert!(check_syntax("cid", "aaaaaaaa"));
    }
}
