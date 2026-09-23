//! Conditional requests: `If-Match` and `If-None-Match` (RFC 9110 §13).
//!
//! Transport-free like the rest of this crate. It takes header *values* and a
//! resource's current version, and says whether a request may go ahead. The
//! version is the `brolly:version` the pod's metadata keeps, a fresh ULID on
//! every change, and the `ETag` is that version in quotes (spec R4). There is
//! one version per resource whatever the representation, so every tag the
//! server issues is strong.
//!
//! **Where it runs.** A write's preconditions are evaluated in
//! `ldp::put_in`, `append_in`, `delete_in` and `patch_in`, after WAC and before
//! the write, inside the `Pod::write` closure. A read's are evaluated by
//! `pod.rs` against the version `ldp::read` returns from its snapshot. Both
//! come after authorisation (RFC 9110 §13.2.1), so a caller without the needed
//! mode gets the ordinary refusal whether or not the resource exists.
//!
//! `If-Modified-Since` and `If-Unmodified-Since` are ignored. The ETag is
//! authoritative, and one-second dates can't tell apart two writes in the same
//! second.

/// One `entity-tag` (RFC 9110 §8.8.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityTag {
    /// Sent with the `W/` prefix.
    pub weak: bool,
    /// What was between the quotes.
    pub opaque: String,
}

impl EntityTag {
    /// Strong comparison: both strong, same opaque value. Ours are always
    /// strong, so a `W/` tag never matches.
    fn strong_eq(&self, version: &str) -> bool {
        !self.weak && self.opaque == version
    }

    /// Weak comparison: same opaque value, prefix ignored.
    fn weak_eq(&self, version: &str) -> bool {
        self.opaque == version
    }
}

/// A parsed `If-Match` or `If-None-Match` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// `*`: any current representation.
    Any,
    /// A list of tags. Empty when the field had nothing usable, which then
    /// matches nothing.
    Tags(Vec<EntityTag>),
}

/// One element of the list, before it is known to be usable.
enum Element {
    Star,
    Tag(EntityTag),
    Malformed,
}

impl Condition {
    /// Parse a field value: `*`, or a comma-separated list of entity tags.
    ///
    /// Robust rather than strict. A malformed element is dropped and the rest
    /// still count, so a stray token can't turn `If-Match` into "anything". A
    /// field with no usable element matches nothing, so `If-Match` fails
    /// closed. A `*` counts only on its own; mixed into a list it's malformed.
    pub fn parse(field: &str) -> Condition {
        let mut tags = Vec::new();
        let mut stars = 0usize;
        let mut elements = 0usize;
        let mut rest = field;
        loop {
            rest = rest.trim_start_matches([' ', '\t', ',']);
            if rest.is_empty() {
                break;
            }
            let (element, after) = next_element(rest);
            rest = after;
            elements += 1;
            match element {
                Element::Star => stars += 1,
                Element::Tag(tag) => tags.push(tag),
                Element::Malformed => {}
            }
        }
        if stars > 0 && stars == elements {
            Condition::Any
        } else {
            Condition::Tags(tags)
        }
    }
}

/// Read one element from the front of `s`, which starts at a non-separator.
/// Returns it and whatever follows, starting at the next `,` or empty.
fn next_element(s: &str) -> (Element, &str) {
    if let Some(after) = s.strip_prefix('*') {
        return finish(Element::Star, after);
    }
    // `W/` is case-sensitive (RFC 9110 §8.8.3: `%s"W/"`).
    let (weak, quoted) = match s.strip_prefix("W/") {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let Some(inner) = quoted.strip_prefix('"') else {
        return skip(s);
    };
    // The closing quote. etagc excludes `"`, so the first one ends the tag.
    let Some(end) = inner.find('"') else {
        return (Element::Malformed, "");
    };
    let (opaque, closing) = inner.split_at(end);
    let after = closing.strip_prefix('"').unwrap_or(closing);
    if !opaque.chars().all(is_etagc) {
        return skip(after);
    }
    finish(
        Element::Tag(EntityTag {
            weak,
            opaque: opaque.to_string(),
        }),
        after,
    )
}

/// After an element only whitespace, then a comma or the end, may follow.
fn finish(element: Element, after: &str) -> (Element, &str) {
    let trimmed = after.trim_start_matches([' ', '\t']);
    if trimmed.is_empty() || trimmed.starts_with(',') {
        (element, trimmed)
    } else {
        skip(trimmed)
    }
}

/// Give up on this element and resume at the next comma.
fn skip(s: &str) -> (Element, &str) {
    match s.find(',') {
        Some(comma) => (Element::Malformed, s.split_at(comma).1),
        None => (Element::Malformed, ""),
    }
}

/// `etagc = %x21 / %x23-7E / obs-text`.
fn is_etagc(c: char) -> bool {
    c == '\x21' || ('\x23'..='\x7e').contains(&c) || !c.is_ascii()
}

/// Which write a precondition guards. The spec's table differs per method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Put,
    Patch,
    Delete,
    /// Evaluated against the container posted to (or the document appended
    /// to), which is the request's target.
    Post,
}

/// A write precondition didn't hold: 412, and nothing written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreconditionFailed;

impl std::fmt::Display for PreconditionFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "precondition failed")
    }
}

impl std::error::Error for PreconditionFailed {}

/// A request's `If-Match` and `If-None-Match`, parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Preconditions {
    pub if_match: Option<Condition>,
    pub if_none_match: Option<Condition>,
}

impl Preconditions {
    /// No conditions: every write and read goes ahead. For callers that aren't
    /// answering an HTTP request.
    pub const NONE: Preconditions = Preconditions {
        if_match: None,
        if_none_match: None,
    };

    /// From the two field values. `None` is an absent header. A header sent on
    /// several lines is passed as one value, the lines joined with `", "`
    /// (RFC 9110 §5.3).
    pub fn from_fields(if_match: Option<&str>, if_none_match: Option<&str>) -> Self {
        Preconditions {
            if_match: if_match.map(Condition::parse),
            if_none_match: if_none_match.map(Condition::parse),
        }
    }

    /// May this write go ahead? `current` is the resource's version, `None`
    /// if it doesn't exist.
    ///
    /// | Field | Methods | Fails when |
    /// |---|---|---|
    /// | `If-Match: *` | all four | the resource doesn't exist |
    /// | `If-Match: "a", …` | all four | no tag strongly matches |
    /// | `If-None-Match: *` | PUT, PATCH | the resource exists |
    /// | `If-None-Match: "a", …` | PUT, PATCH, DELETE | a tag weakly matches |
    pub fn check_write(
        &self,
        method: Method,
        current: Option<&str>,
    ) -> Result<(), PreconditionFailed> {
        if let Some(condition) = &self.if_match {
            let holds = match (condition, current) {
                (_, None) => false,
                (Condition::Any, Some(_)) => true,
                (Condition::Tags(tags), Some(version)) => {
                    tags.iter().any(|tag| tag.strong_eq(version))
                }
            };
            if !holds {
                return Err(PreconditionFailed);
            }
        }
        if let Some(condition) = &self.if_none_match {
            let fails = match (condition, current) {
                (_, None) => false,
                (Condition::Any, Some(_)) => matches!(method, Method::Put | Method::Patch),
                (Condition::Tags(tags), Some(version)) => {
                    method != Method::Post && tags.iter().any(|tag| tag.weak_eq(version))
                }
            };
            if fails {
                return Err(PreconditionFailed);
            }
        }
        Ok(())
    }

    /// Should a GET or HEAD of a resource at `current` answer 304?
    ///
    /// Only `If-None-Match` counts on a read. `If-Match` on a GET is ignored,
    /// as in the spec's table.
    pub fn not_modified(&self, current: &str) -> bool {
        match &self.if_none_match {
            None => false,
            Some(Condition::Any) => true,
            Some(Condition::Tags(tags)) => tags.iter().any(|tag| tag.weak_eq(current)),
        }
    }
}

/// The `ETag` for a version: the version in quotes, strong.
pub fn etag(version: &str) -> String {
    format!("\"{version}\"")
}

/// `dcterms:modified` as an HTTP-date (IMF-fixdate, RFC 9110 §5.6.7), for
/// `Last-Modified`.
///
/// `modified` is the `xsd:dateTime` lexical form `resources.rs` writes:
/// `YYYY-MM-DDTHH:MM:SS.mmmZ`, UTC. `+00:00` is accepted too. Anything else
/// (no zone, another offset, a date that doesn't exist) is `None`, and the
/// response goes out without `Last-Modified` rather than with a wrong one.
/// Parsed by hand because this crate's `time` has `formatting` but not
/// `parsing`, and the format is fixed.
pub fn http_date(modified: &str) -> Option<String> {
    use time::{Date, Month, Time, Weekday};

    let (date, rest) = modified.split_once('T')?;
    let clock = rest
        .strip_suffix('Z')
        .or_else(|| rest.strip_suffix("+00:00"))?;
    // HTTP-dates have one-second precision.
    let clock = clock.split('.').next()?;

    let mut ymd = date.splitn(3, '-');
    let year: i32 = ymd.next()?.parse().ok()?;
    let month: u8 = ymd.next()?.parse().ok()?;
    let day: u8 = ymd.next()?.parse().ok()?;

    let mut hms = clock.splitn(3, ':');
    let hour: u8 = hms.next()?.parse().ok()?;
    let minute: u8 = hms.next()?.parse().ok()?;
    let second: u8 = hms.next()?.parse().ok()?;

    let month = Month::try_from(month).ok()?;
    let date = Date::from_calendar_date(year, month, day).ok()?;
    Time::from_hms(hour, minute, second).ok()?;

    let weekday = match date.weekday() {
        Weekday::Monday => "Mon",
        Weekday::Tuesday => "Tue",
        Weekday::Wednesday => "Wed",
        Weekday::Thursday => "Thu",
        Weekday::Friday => "Fri",
        Weekday::Saturday => "Sat",
        Weekday::Sunday => "Sun",
    };
    let month = match month {
        Month::January => "Jan",
        Month::February => "Feb",
        Month::March => "Mar",
        Month::April => "Apr",
        Month::May => "May",
        Month::June => "Jun",
        Month::July => "Jul",
        Month::August => "Aug",
        Month::September => "Sep",
        Month::October => "Oct",
        Month::November => "Nov",
        Month::December => "Dec",
    };
    Some(format!(
        "{weekday}, {day:02} {month} {year:04} {hour:02}:{minute:02}:{second:02} GMT"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Method; 4] = [Method::Put, Method::Patch, Method::Delete, Method::Post];

    fn strong(s: &str) -> EntityTag {
        EntityTag {
            weak: false,
            opaque: s.to_string(),
        }
    }

    fn weak(s: &str) -> EntityTag {
        EntityTag {
            weak: true,
            opaque: s.to_string(),
        }
    }

    fn with(if_match: Option<&str>, if_none_match: Option<&str>) -> Preconditions {
        Preconditions::from_fields(if_match, if_none_match)
    }

    // --- parsing ---------------------------------------------------------------

    #[test]
    fn a_star_alone_is_any() {
        assert_eq!(Condition::parse("*"), Condition::Any);
        assert_eq!(Condition::parse("  *\t"), Condition::Any);
        assert_eq!(Condition::parse("*, *"), Condition::Any);
    }

    #[test]
    fn a_list_is_quoted_tags_separated_by_commas() {
        assert_eq!(
            Condition::parse(r#""a", W/"b" ,"c""#),
            Condition::Tags(vec![strong("a"), weak("b"), strong("c")])
        );
        // RFC 9110 §5.6.1: a recipient accepts empty list elements.
        assert_eq!(
            Condition::parse(r#", "a",, "b","#),
            Condition::Tags(vec![strong("a"), strong("b")])
        );
    }

    #[test]
    fn a_comma_inside_the_quotes_belongs_to_the_tag() {
        // etagc includes ",", so splitting on commas first would be wrong.
        assert_eq!(
            Condition::parse(r#""a,b", "c""#),
            Condition::Tags(vec![strong("a,b"), strong("c")])
        );
    }

    #[test]
    fn malformed_elements_are_dropped_and_the_rest_kept() {
        // Unquoted, a lower-case weak prefix, junk after the quote, and a star
        // inside a list are each malformed on their own.
        assert_eq!(
            Condition::parse(r#"abc, w/"x", "y"z, *, "ok""#),
            Condition::Tags(vec![strong("ok")])
        );
        assert_eq!(
            Condition::parse(r#""ok", "unterminated"#),
            Condition::Tags(vec![strong("ok")])
        );
        // A space isn't etagc.
        assert_eq!(Condition::parse(r#""a b""#), Condition::Tags(vec![]));
        assert_eq!(Condition::parse(""), Condition::Tags(vec![]));
    }

    #[test]
    fn an_absent_field_is_no_condition() {
        assert_eq!(with(None, None), Preconditions::NONE);
        assert_eq!(with(Some(""), None).if_match, Some(Condition::Tags(vec![])));
    }

    // --- writes ----------------------------------------------------------------

    #[test]
    fn no_conditions_always_hold() {
        for method in ALL {
            assert_eq!(Preconditions::NONE.check_write(method, None), Ok(()));
            assert_eq!(Preconditions::NONE.check_write(method, Some("v")), Ok(()));
        }
        assert!(!Preconditions::NONE.not_modified("v"));
    }

    #[test]
    fn if_match_star_needs_a_current_resource() {
        let p = with(Some("*"), None);
        for method in ALL {
            assert_eq!(p.check_write(method, None), Err(PreconditionFailed));
            assert_eq!(p.check_write(method, Some("v")), Ok(()));
        }
    }

    #[test]
    fn if_match_compares_strongly() {
        let p = with(Some(r#""old", "v""#), None);
        for method in ALL {
            assert_eq!(p.check_write(method, Some("v")), Ok(()));
            assert_eq!(p.check_write(method, Some("new")), Err(PreconditionFailed));
            assert_eq!(p.check_write(method, None), Err(PreconditionFailed));
        }
        // A weak tag never matches, even with the right opaque value.
        assert_eq!(
            with(Some(r#"W/"v""#), None).check_write(Method::Put, Some("v")),
            Err(PreconditionFailed)
        );
        // A field with nothing usable in it holds for nothing: fail closed.
        assert_eq!(
            with(Some("v"), None).check_write(Method::Put, Some("v")),
            Err(PreconditionFailed)
        );
    }

    #[test]
    fn if_none_match_star_guards_creation_on_put_and_patch_only() {
        let p = with(None, Some("*"));
        for method in [Method::Put, Method::Patch] {
            assert_eq!(p.check_write(method, Some("v")), Err(PreconditionFailed));
            assert_eq!(p.check_write(method, None), Ok(()));
        }
        // Not in the spec's table for DELETE or POST.
        assert_eq!(p.check_write(Method::Delete, Some("v")), Ok(()));
        assert_eq!(p.check_write(Method::Post, Some("v")), Ok(()));
    }

    #[test]
    fn if_none_match_tags_refuse_the_current_version() {
        let p = with(None, Some(r#""old", "v""#));
        for method in [Method::Put, Method::Patch, Method::Delete] {
            assert_eq!(p.check_write(method, Some("v")), Err(PreconditionFailed));
            assert_eq!(p.check_write(method, Some("new")), Ok(()));
            assert_eq!(p.check_write(method, None), Ok(()));
        }
        // Not in the spec's table for POST.
        assert_eq!(p.check_write(Method::Post, Some("v")), Ok(()));
        // RFC 9110 §13.1.2: If-None-Match uses the weak comparison.
        assert_eq!(
            with(None, Some(r#"W/"v""#)).check_write(Method::Put, Some("v")),
            Err(PreconditionFailed)
        );
    }

    #[test]
    fn both_fields_must_hold() {
        let p = with(Some(r#""v""#), Some("*"));
        assert_eq!(
            p.check_write(Method::Put, Some("v")),
            Err(PreconditionFailed)
        );
    }

    // --- reads -----------------------------------------------------------------

    #[test]
    fn a_read_is_not_modified_when_if_none_match_matches() {
        assert!(with(None, Some(r#""v""#)).not_modified("v"));
        assert!(with(None, Some(r#""old", W/"v""#)).not_modified("v"));
        assert!(with(None, Some("*")).not_modified("v"));
        assert!(!with(None, Some(r#""old""#)).not_modified("v"));
        // If-Match isn't evaluated on a read.
        assert!(!with(Some(r#""old""#), None).not_modified("v"));
    }

    // --- headers out -------------------------------------------------------------

    #[test]
    fn an_etag_is_the_version_in_quotes() {
        assert_eq!(
            etag("01J8Z3T5V7W9X1Y3Z5A7B9C1D3"),
            r#""01J8Z3T5V7W9X1Y3Z5A7B9C1D3""#
        );
    }

    #[test]
    fn last_modified_is_an_imf_fixdate() {
        // RFC 9110 §5.6.7's own example.
        assert_eq!(
            http_date("1994-11-06T08:49:37.000Z").as_deref(),
            Some("Sun, 06 Nov 1994 08:49:37 GMT")
        );
        // Milliseconds are dropped: an HTTP-date has one-second precision.
        assert_eq!(
            http_date("2026-09-22T09:05:03.999Z").as_deref(),
            Some("Tue, 22 Sep 2026 09:05:03 GMT")
        );
        assert_eq!(
            http_date("2024-02-29T23:59:59+00:00").as_deref(),
            Some("Thu, 29 Feb 2024 23:59:59 GMT")
        );
        assert_eq!(http_date("2026-09-22T09:05:03"), None, "no zone");
        assert_eq!(http_date("2026-09-22T09:05:03+02:00"), None, "not UTC");
        assert_eq!(http_date("2026-02-30T00:00:00Z"), None, "no such day");
        assert_eq!(http_date("not a date"), None);
    }
}
