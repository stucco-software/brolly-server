//! Mastodon status IDs: sortable, fixed-width, self-describing (ADR 0015).
//!
//! A status ID is a ULID naming the note, followed by the owning member's UUID,
//! both in Crockford base32:
//!
//! ```text
//!   01J5X8QK9V7T2M4N6P8R0S1T3W   ZWK41RG4Z44M7CG5RB0BQ0M1G1
//!   └── note ULID, 26 chars ──┘  └── owner UUID, 26 chars ─┘
//! ```
//!
//! Resolving one is a decode plus a primary-key lookup on `users` — no index,
//! no routing table, no extra column (ADR 0005 R2). That is also why the
//! Mastodon crate needs no store access to resolve an ID, which is what Phase
//! 6's projection-only rule wants anyway.
//!
//! **Both halves are fixed width, and that is load-bearing rather than tidy.**
//! Mastodon's own docs tell clients to sort by length before sorting lexically.
//! Any variation in width and that first clause starts deciding order — a
//! member with a longer identifier would sort as permanently newer. Constant
//! width makes the clause a no-op and leaves the ULID prefix in charge.

use uuid::Uuid;

/// Crockford base32. `I`, `L`, `O` and `U` are absent, so an ID retyped from a
/// screenshot or read aloud cannot quietly become a different one.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Characters in one encoded 128-bit value. 26 × 5 = 130 bits, so two bits of
/// leading pad.
const HALF: usize = 26;

/// Total width of a status ID. Every ID is exactly this long, always.
pub const WIDTH: usize = HALF * 2;

/// Encode 128 bits as 26 Crockford base32 characters, most significant first.
fn encode_128(bytes: [u8; 16]) -> String {
    let value = u128::from_be_bytes(bytes);
    let mut out = [0u8; HALF];
    for (i, slot) in out.iter_mut().enumerate().rev() {
        // `i == 0` holds the two pad bits plus three real ones; the shift below
        // is still in range because the value is only 128 bits wide.
        let shift = 5 * (HALF - 1 - i);
        *slot = ALPHABET[((value >> shift) & 0x1f) as usize];
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn decode_128(text: &str) -> Option<[u8; 16]> {
    if text.len() != HALF {
        return None;
    }
    let mut value: u128 = 0;
    for c in text.bytes() {
        // Uppercase only. Accepting lowercase too would give every status two
        // spellings, and equality on IDs is used to dedupe.
        let digit = ALPHABET.iter().position(|a| *a == c)? as u128;
        // The first character carries the two pad bits; anything that would
        // overflow 128 bits is not something we minted.
        value = value.checked_mul(32)?.checked_add(digit)?;
    }
    Some(value.to_be_bytes())
}

/// Mint a note's local identifier: a ULID over `now_ms` and `randomness`.
///
/// The timestamp occupies the high 48 bits, which is what makes the encoding
/// sort chronologically. `randomness` breaks ties inside a millisecond.
///
/// Both inputs are passed rather than read so ordering is testable without
/// sleeping and without a clock.
pub fn new_note_id(now_ms: u64, randomness: [u8; 10]) -> String {
    let mut bytes = [0u8; 16];
    bytes[..6].copy_from_slice(&now_ms.to_be_bytes()[2..]);
    bytes[6..].copy_from_slice(&randomness);
    encode_128(bytes)
}

/// Mint a note id from the current clock.
pub fn mint_note_id() -> String {
    let now_ms = (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).max(0) as u64;
    new_note_id(now_ms, rand::random())
}

/// True if `text` is a well-formed note identifier.
///
/// Phase 5 minted note IRIs with UUIDv4 local parts, which are not sortable.
/// Letting one through would produce an ID that claims an ordering it does not
/// have.
pub fn is_note_id(text: &str) -> bool {
    decode_128(text).is_some()
}

/// Combine a note's ULID with its owner into a status ID.
///
/// `None` when the note identifier is not a ULID — see [`is_note_id`].
pub fn encode(note_id: &str, owner: Uuid) -> Option<String> {
    if !is_note_id(note_id) {
        return None;
    }
    Some(format!("{note_id}{}", encode_128(*owner.as_bytes())))
}

/// Split a status ID back into its note identifier and owning member.
///
/// `None` for anything we did not mint. A status ID that half-parsed would
/// resolve to the wrong member's pod.
pub fn decode(status_id: &str) -> Option<(String, Uuid)> {
    if status_id.len() != WIDTH {
        return None;
    }
    let (note, owner) = status_id.split_at(HALF);
    if !is_note_id(note) {
        return None;
    }
    Some((note.to_string(), Uuid::from_bytes(decode_128(owner)?)))
}

/// Rebuild the note's IRI, given the username the owner UUID resolved to.
///
/// The IRI already names its owner, which is the property that makes the whole
/// scheme unnecessary for anything except Mastodon's opaque IDs.
pub fn note_iri(note_id: &str, username: &str, base_domain: &str) -> String {
    format!("https://{username}.{base_domain}/~/notes/{note_id}")
}

/// Recover the note identifier from an IRI this instance minted.
pub fn note_id_from_iri(iri: &str) -> Option<&str> {
    let (_, id) = iri.rsplit_once("/~/notes/")?;
    is_note_id(id).then_some(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_encoding_is_stable_for_a_known_value() {
        // Pins the bit layout. If this changes, every ID ever issued changes
        // meaning, so it should fail loudly rather than drift.
        assert_eq!(encode_128([0; 16]), "0".repeat(26));
        assert_eq!(encode_128([0xff; 16]), format!("7{}", "Z".repeat(25)));
    }

    #[test]
    fn encoding_round_trips_across_the_range() {
        for bytes in [
            [0u8; 16],
            [0xffu8; 16],
            [1u8; 16],
            *Uuid::parse_str("3f2504e0-4f89-11d3-9a0c-0305e82c3301")
                .unwrap()
                .as_bytes(),
        ] {
            assert_eq!(decode_128(&encode_128(bytes)), Some(bytes));
        }
    }

    #[test]
    fn the_timestamp_lands_in_the_high_bits() {
        // What makes the encoding sort chronologically at all.
        let early = new_note_id(1, [0xff; 10]);
        let late = new_note_id(2, [0x00; 10]);
        assert!(
            early < late,
            "randomness outranked the timestamp: {early} vs {late}"
        );
    }

    #[test]
    fn an_out_of_range_encoding_is_refused() {
        // 26 Crockford characters can express 130 bits; only 128 are real. An
        // id whose leading character sets a pad bit was not minted here.
        assert!(decode_128(&format!("8{}", "0".repeat(25))).is_none());
        assert!(decode_128(&format!("Z{}", "Z".repeat(25))).is_none());
    }

    #[test]
    fn a_note_id_survives_a_trip_through_an_iri() {
        let note = new_note_id(1_724_000_000_000, [5; 10]);
        let iri = note_iri(&note, "alice", "brolly.test");
        assert_eq!(note_id_from_iri(&iri), Some(note.as_str()));
    }

    #[test]
    fn a_foreign_iri_yields_no_note_id() {
        assert_eq!(
            note_id_from_iri("https://mastodon.social/users/alice/statuses/1"),
            None
        );
        assert_eq!(
            note_id_from_iri("https://alice.brolly.test/~/notes/not-a-ulid"),
            None
        );
    }
}
