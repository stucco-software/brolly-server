//! The media gate: what this server stores, and how much of it (spec 4).
//!
//! Two allow-lists — media, and the documents a web site is made of (ADR
//! 0018) — and one size limit, all enforced at the single choke point every
//! protocol's binary already passes through (`ldp::prepare`). The media list
//! and the limit are advertised by the Mastodon instance configuration, and
//! the media list has a second check at the Mastodon upload, so an attachment
//! stays media. The stage's premise is that an advertised contract nothing
//! keeps is a bug, and the tests here and in `brolly-mastodon`'s instance
//! module are what keep them from drifting apart silently.

/// The content types this server stores as media (spec 4, H2).
///
/// A binary is stored only if its content type — parameters stripped, as
/// [`crate::syntax::media_type_of`] produces — is on this list or on
/// [`ALLOWED_DOCUMENT_TYPES`] (ADR 0018). Anything else is a 415 with both
/// lists in the body: the type is syntactically fine, this server just
/// doesn't store it. Before any list, a member-typed `text/html` on the
/// member's own origin was stored XSS: the bytes were served back with the
/// type the uploader chose, on the origin that then held the member's
/// session. It holds none now (ADR 0018).
///
/// **`text/html` and `image/svg+xml` are not here — they are on
/// [`ALLOWED_DOCUMENT_TYPES`].** This list is what a Mastodon *attachment*
/// may be; the pod stores both lists (ADR 0018). Spec 4 kept the two off
/// every list while a member's origin held the member's session; it holds
/// none now, and the decision is reversed on the record.
///
/// The six RDF syntaxes and ADR 0007's `rdf+xml` refusal are upstream of this
/// list and unchanged: a parseable RDF type never reaches the binary branch,
/// and `rdf+xml` is refused outright rather than stored as a blob.
///
/// `text/plain` and friends are here, not in the graph store: they are not RDF
/// syntaxes, and plain text is not script.
pub const ALLOWED_MEDIA_TYPES: &[&str] = &[
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "image/avif",
    "audio/mpeg",
    "audio/ogg",
    "audio/wav",
    "audio/flac",
    "audio/webm",
    "video/mp4",
    "video/webm",
    "application/pdf",
    "application/zip",
    "text/plain",
    "text/markdown",
    "text/csv",
    "application/octet-stream",
];

/// The document types a web site is made of (ADR 0018): what a pod stores
/// and serves as typed, beyond media. Kept apart from
/// [`ALLOWED_MEDIA_TYPES`] so that a Mastodon upload — which checks the
/// media list before the pod's gate — cannot become an HTML upload. No
/// `application/wasm`: it needs script to run and nobody has asked.
pub const ALLOWED_DOCUMENT_TYPES: &[&str] = &[
    "text/html",
    "text/css",
    "text/javascript",
    "application/javascript",
    "application/json",
    "application/manifest+json",
    "image/svg+xml",
    "image/x-icon",
    "image/vnd.microsoft.icon",
    "font/woff2",
    "font/woff",
    "font/ttf",
    "font/otf",
    "application/xml",
    "text/xml",
    "application/rss+xml",
    "application/atom+xml",
];

/// The upload limit this server enforces, and the one it advertises (spec 4,
/// H3).
///
/// `DefaultBodyLimit` on the pod and media routes, overridable with
/// `BROLLY_MAX_UPLOAD_BYTES`; the Mastodon instance configuration's
/// `image_size_limit` is this same constant, with a test asserting the two are
/// equal — an advertised limit and an enforced limit that differ is the bug
/// this stage closes. The limit is bytes-on-the-wire: a multipart file at
/// exactly this number 413s, because its framing counts too. Accepted — the
/// one constant is worth more than a fudge factor.
pub const MAX_UPLOAD_BYTES: usize = 10 * 1024 * 1024;

/// How much a member's pod may hold, by default — every byte under its
/// directory, the RDF store and the blobs alike — before a write is refused
/// with 507. `BROLLY_POD_QUOTA_BYTES` overrides it. A pod's floor is a few
/// hundred kilobytes of store before anything is written (ADR 0006), which
/// is why the number is a gigabyte and not a figure a small instance would
/// have to raise on its first day. The quota is the instance's defence
/// against a caller with Append on one public container filling the disk,
/// not a product tier: it bounds the damage one grant can do.
pub const DEFAULT_POD_QUOTA_BYTES: u64 = 1024 * 1024 * 1024;

/// What is wrong with a string that is not a size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SizeError {
    Empty,
    NotANumber,
    UnknownUnit(String),
    /// Above `i64::MAX`: the column is `BIGINT`, and nothing larger is a
    /// meaningful quota.
    TooLarge,
}

impl std::fmt::Display for SizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SizeError::Empty => write!(f, "a size is required"),
            SizeError::NotANumber => write!(
                f,
                "a size is a number, optionally with a decimal fraction, then K, M, G or T"
            ),
            SizeError::UnknownUnit(unit) => {
                write!(f, "{unit} is not a unit; use K, M, G or T (binary)")
            }
            SizeError::TooLarge => write!(f, "that is larger than any quota can be"),
        }
    }
}

impl std::error::Error for SizeError {}

/// The units `format_size` prints, and their byte counts; `parse_size`
/// accepts these and their short and `…B` spellings.
const SIZE_UNITS: [(&str, u64); 4] = [
    ("KiB", 1 << 10),
    ("MiB", 1 << 20),
    ("GiB", 1 << 30),
    ("TiB", 1 << 40),
];

/// `"5G"`, `"512M"`, `"100K"`, `"5GiB"`, `"512 MiB"`, `"1.5G"`, `"1024"` — a
/// number with an optional decimal fraction, then a binary unit (K, M, G,
/// T; case-insensitive; an optional `iB` or `B` after it; whitespace
/// tolerated between number and unit), or plain digits for bytes. The
/// result is rounded down to a whole byte and never exceeds `i64::MAX`.
/// Nothing else parses.
///
/// A fraction is allowed so that every string [`format_size`] prints parses
/// back: the console prefills its field with the formatted override, and an
/// admin who saves a row untouched must not be refused a value the system
/// itself displayed.
pub fn parse_size(text: &str) -> Result<u64, SizeError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(SizeError::Empty);
    }
    let split = text
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    // Before the unit: `-1` and `G` have no number, and the unit is not
    // where that is reported.
    if number.is_empty() {
        return Err(SizeError::NotANumber);
    }
    // Matched lowercased, reported as typed.
    let unit = unit.trim();
    let multiplier = match unit.to_ascii_lowercase().as_str() {
        "" | "b" => 1u64,
        "k" | "kb" | "kib" => 1 << 10,
        "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        "t" | "tb" | "tib" => 1 << 40,
        _ => return Err(SizeError::UnknownUnit(unit.to_string())),
    };

    let (whole, fraction) = match number.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (number, None),
    };
    if whole.is_empty() || fraction == Some("") {
        return Err(SizeError::NotANumber);
    }
    // A fraction of a byte is nothing.
    if fraction.is_some() && multiplier == 1 {
        return Err(SizeError::NotANumber);
    }
    // All digits by now, so the only way this fails is a number too long
    // for u128: too large, not "not a number".
    let whole: u128 = whole.parse().map_err(|_| SizeError::TooLarge)?;
    // Up to eighteen fractional digits are exact in u128; more cannot
    // change a byte count at any unit this grammar names.
    let fraction = fraction.unwrap_or("");
    if !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SizeError::NotANumber);
    }
    let fraction = &fraction[..fraction.len().min(18)];
    let fraction_value: u128 = if fraction.is_empty() {
        0
    } else {
        fraction.parse().map_err(|_| SizeError::NotANumber)?
    };
    let scale = 10u128.pow(fraction.len() as u32);

    let bytes = whole
        .checked_mul(u128::from(multiplier))
        .and_then(|b| b.checked_add(fraction_value * u128::from(multiplier) / scale))
        .ok_or(SizeError::TooLarge)?;
    if bytes > i64::MAX as u128 {
        return Err(SizeError::TooLarge);
    }
    Ok(bytes as u64)
}

/// The inverse of [`parse_size`], for display: the largest binary unit not
/// exceeding the value; printed whole when the value is an exact multiple
/// of it, else to one decimal, *rounded down* — `5 GiB`, `512 MiB`,
/// `1.5 GiB`, `412.5 MiB`, `1023.9 MiB`, `1023 B`, `0 B`. A string
/// `parse_size` accepts for any value up to `i64::MAX` — the ceiling
/// `parse_size` enforces and the column holds — and never more than the
/// value it was given: rounding to nearest would print `1024.0 MiB` for a
/// byte under a gibibyte and `8388608.0 TiB` for `i64::MAX` — which parses
/// as too large, so a value the console displayed would be refused on an
/// untouched save.
pub fn format_size(bytes: u64) -> String {
    for (name, unit) in SIZE_UNITS.iter().rev() {
        if bytes >= *unit {
            if bytes.is_multiple_of(*unit) {
                return format!("{} {name}", bytes / unit);
            }
            let tenths = u128::from(bytes) * 10 / u128::from(*unit);
            return format!("{}.{} {name}", tenths / 10, tenths % 10);
        }
    }
    format!("{bytes} B")
}

/// True when `media_type` — a bare, parameter-stripped type — is one a
/// Mastodon attachment may be. The stripping is the caller's
/// ([`crate::syntax::media_type_of`]): `image/png; charset=utf-8` is
/// `image/png`.
pub fn is_allowed_media_type(media_type: &str) -> bool {
    ALLOWED_MEDIA_TYPES.contains(&media_type)
}

/// True when the pod stores `media_type` as a binary: media or a document
/// (ADR 0018). The one question `ldp::prepare` asks.
pub fn is_storable_type(media_type: &str) -> bool {
    is_allowed_media_type(media_type) || ALLOWED_DOCUMENT_TYPES.contains(&media_type)
}

/// The type a binary is recorded and served with, from the `Content-Type` it
/// was sent with: the bare type, plus `; charset=…` when the type is textual
/// and one was sent (ADR 0018). A page's charset is part of what it is — a
/// non-ASCII page without `<meta charset>` garbles without it. Only
/// `charset`, lowercased and unquoted; every other parameter is dropped, so
/// `image/png` and `image/png; name=x` stay one type for the same bytes. A
/// value that is not a plain charset name is dropped rather than echoed.
pub fn recorded_type(content_type: &str) -> String {
    let bare = crate::syntax::media_type_of(content_type);
    let charset = is_textual(bare)
        .then(|| {
            content_type.split(';').skip(1).find_map(|parameter| {
                let (name, value) = parameter.split_once('=')?;
                name.trim()
                    .eq_ignore_ascii_case("charset")
                    .then(|| value.trim().trim_matches('"').to_ascii_lowercase())
            })
        })
        .flatten()
        .filter(|value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.:+".contains(&b))
        });
    match charset {
        Some(charset) => format!("{bare}; charset={charset}"),
        None => bare.to_string(),
    }
}

/// True for a type whose bytes are text, so a charset means something.
fn is_textual(bare: &str) -> bool {
    bare.starts_with("text/")
        || bare.ends_with("+xml")
        || bare.ends_with("+json")
        || matches!(
            bare,
            "application/json" | "application/xml" | "application/javascript"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_is_what_the_spec_names() {
        // The spec's own block, in its order, so a diff against the spec is
        // readable. `application/octet-stream` last, as the catch-all a
        // type-less client gets.
        assert_eq!(
            ALLOWED_MEDIA_TYPES,
            &[
                "image/jpeg",
                "image/png",
                "image/gif",
                "image/webp",
                "image/avif",
                "audio/mpeg",
                "audio/ogg",
                "audio/wav",
                "audio/flac",
                "audio/webm",
                "video/mp4",
                "video/webm",
                "application/pdf",
                "application/zip",
                "text/plain",
                "text/markdown",
                "text/csv",
                "application/octet-stream",
            ]
        );
    }

    #[test]
    fn the_document_list_is_what_the_adr_names() {
        // ADR 0018's block, in its order.
        assert_eq!(
            ALLOWED_DOCUMENT_TYPES,
            &[
                "text/html",
                "text/css",
                "text/javascript",
                "application/javascript",
                "application/json",
                "application/manifest+json",
                "image/svg+xml",
                "image/x-icon",
                "image/vnd.microsoft.icon",
                "font/woff2",
                "font/woff",
                "font/ttf",
                "font/otf",
                "application/xml",
                "text/xml",
                "application/rss+xml",
                "application/atom+xml",
            ]
        );
    }

    #[test]
    fn a_document_is_storable_but_is_not_media() {
        // Two lists, one gate (ADR 0018): the pod stores both; a Mastodon
        // attachment is media only. SVG and HTML are the two the old list
        // kept out by decision, and the decision is reversed here, on the
        // record.
        for document in [
            "text/html",
            "image/svg+xml",
            "text/css",
            "application/rss+xml",
        ] {
            assert!(is_storable_type(document), "{document}");
            assert!(!is_allowed_media_type(document), "{document}");
        }
        for medium in ["image/png", "application/pdf", "text/plain"] {
            assert!(is_storable_type(medium), "{medium}");
            assert!(is_allowed_media_type(medium), "{medium}");
        }
        for neither in ["application/x-sh", "application/rdf+xml", "text/turtle"] {
            assert!(!is_storable_type(neither), "{neither}");
        }
        // The two lists do not overlap: a type is one thing or the other.
        for document in ALLOWED_DOCUMENT_TYPES {
            assert!(
                !ALLOWED_MEDIA_TYPES.contains(document),
                "{document} is on both"
            );
        }
    }

    #[test]
    fn a_textual_type_is_recorded_with_its_charset_and_nothing_else() {
        for (sent, recorded) in [
            ("text/html; charset=utf-8", "text/html; charset=utf-8"),
            ("text/html;charset=UTF-8", "text/html; charset=utf-8"),
            (
                "text/css; Charset=\"UTF-8\"; foo=bar",
                "text/css; charset=utf-8",
            ),
            (
                "image/svg+xml; charset=utf-8",
                "image/svg+xml; charset=utf-8",
            ),
            (
                "application/json; charset=utf-8",
                "application/json; charset=utf-8",
            ),
            ("text/html", "text/html"),
            ("text/html; foo=bar", "text/html"),
            // A binary has no charset to keep.
            ("image/png; charset=utf-8", "image/png"),
            ("image/png; foo=bar", "image/png"),
            // A value that is not a charset name is dropped, not echoed.
            ("text/html; charset=\"utf 8\"", "text/html"),
            ("text/html; charset=", "text/html"),
        ] {
            assert_eq!(recorded_type(sent), recorded, "{sent}");
        }
    }

    #[test]
    fn sizes_parse_in_binary_units_with_optional_suffixes() {
        for (text, bytes) in [
            ("5G", 5 * 1024 * 1024 * 1024),
            ("5g", 5 * 1024 * 1024 * 1024),
            ("5GiB", 5 * 1024 * 1024 * 1024),
            ("5 GB", 5 * 1024 * 1024 * 1024),
            ("512 MiB", 512 * 1024 * 1024),
            ("100K", 100 * 1024),
            ("2T", 2 * 1024 * 1024 * 1024 * 1024),
            ("1.5G", 1024 * 1024 * 1024 + 512 * 1024 * 1024),
            ("0.5M", 512 * 1024),
            ("1024", 1024),
            ("0", 0),
            ("  7M  ", 7 * 1024 * 1024),
        ] {
            assert_eq!(parse_size(text), Ok(bytes), "{text:?}");
        }
    }

    #[test]
    fn a_fraction_rounds_down_to_a_whole_byte() {
        // 1.0000001 KiB is 1024.0001… bytes: 1024.
        assert_eq!(parse_size("1.0000001K"), Ok(1024));
    }

    #[test]
    fn what_is_not_a_size_is_refused_by_name() {
        assert_eq!(parse_size(""), Err(SizeError::Empty));
        assert_eq!(parse_size("   "), Err(SizeError::Empty));
        assert_eq!(parse_size("-1"), Err(SizeError::NotANumber));
        assert_eq!(parse_size("G"), Err(SizeError::NotANumber));
        assert_eq!(parse_size(".5G"), Err(SizeError::NotANumber));
        assert_eq!(parse_size("1.2.3G"), Err(SizeError::NotANumber));
        // A second point past the eighteenth fractional character is still
        // not a number: the fraction is checked before it is cut.
        assert_eq!(
            parse_size("1.000000000000000000.5G"),
            Err(SizeError::NotANumber)
        );
        // A fraction of a byte is nothing.
        assert_eq!(parse_size("1.5"), Err(SizeError::NotANumber));
        assert_eq!(parse_size("5X"), Err(SizeError::UnknownUnit("X".into())));
        assert_eq!(
            parse_size("5 bytes"),
            Err(SizeError::UnknownUnit("bytes".into()))
        );
        // The column is BIGINT: nothing above i64::MAX is a quota.
        assert_eq!(parse_size("99999999999G"), Err(SizeError::TooLarge));
        // Too long for any integer type is too large, not "not a number".
        assert_eq!(
            parse_size("1000000000000000000000000000000000000000"),
            Err(SizeError::TooLarge)
        );
        assert_eq!(parse_size("9223372036854775807"), Ok(i64::MAX as u64));
        assert_eq!(parse_size("9223372036854775808"), Err(SizeError::TooLarge));
    }

    #[test]
    fn sizes_print_whole_when_exact_else_to_one_decimal() {
        for (bytes, text) in [
            (5 * 1024 * 1024 * 1024, "5 GiB"),
            (512 * 1024 * 1024, "512 MiB"),
            (1024 * 1024 * 1024 + 512 * 1024 * 1024, "1.5 GiB"),
            (432_537_600, "412.5 MiB"),
            (1024 * 1024 * 1024 - 1, "1023.9 MiB"),
            (1023, "1023 B"),
            (0, "0 B"),
            (1024, "1 KiB"),
            (3 * 1024 * 1024 * 1024 * 1024, "3 TiB"),
            (i64::MAX as u64, "8388607.9 TiB"),
        ] {
            assert_eq!(format_size(bytes), text, "{bytes}");
        }
    }

    #[test]
    fn every_printed_size_parses_and_whole_units_round_trip() {
        for bytes in [
            0u64,
            1,
            1023,
            1024,
            1536,
            432_537_600,
            5 * 1024 * 1024 * 1024,
            1024 * 1024 * 1024 - 1,
            i64::MAX as u64,
        ] {
            let printed = format_size(bytes);
            let back = parse_size(&printed).unwrap_or_else(|e| panic!("{printed}: {e}"));
            // Within a tenth of the unit printed, and never above: what the
            // display promised, rounded down.
            let unit = unit_of(&printed);
            assert!(
                back <= bytes && bytes - back <= unit / 10 + 1,
                "{bytes} -> {printed} -> {back}"
            );
        }
        for bytes in [1024u64, 7 * 1024 * 1024, 2 * 1024 * 1024 * 1024] {
            assert_eq!(
                parse_size(&format_size(bytes)),
                Ok(bytes),
                "exact round trip"
            );
        }
    }

    /// The unit a printed size names, in bytes — a helper for the test above.
    fn unit_of(printed: &str) -> u64 {
        match printed.rsplit(' ').next() {
            Some("TiB") => 1 << 40,
            Some("GiB") => 1 << 30,
            Some("MiB") => 1 << 20,
            Some("KiB") => 1 << 10,
            _ => 1,
        }
    }
}
