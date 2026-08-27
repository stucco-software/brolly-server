//! Status IDs (ADR 0015).
//!
//! Mastodon's API contract calls IDs opaque strings, but the official docs also
//! publish a client-side sorting recipe — "sort by length, newer statuses will
//! have longer IDs; then sort lexically" — and every shipped implementation
//! that moved off numeric IDs kept them lexically sortable. So the ID has to be
//! sortable whether or not any particular client sorts.
//!
//! Two properties carry the whole design, and both are asserted here:
//!
//! * **Chronological order equals lexical order**, so a client that sorts gets
//!   the same answer the server intended.
//! * **Fixed width**, so the recipe's "sort by length first" clause degenerates
//!   to a plain lexical sort. Variable width would make a member with a longer
//!   name sort as permanently newer.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_mastodon::status_id;
use uuid::Uuid;

const OWNER: &str = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const OTHER_OWNER: &str = "00000000-0000-0000-0000-000000000001";

fn owner() -> Uuid {
    Uuid::parse_str(OWNER).unwrap()
}

/// A note id minted at a fixed instant, so ordering assertions are exact.
fn note_at(ms: u64, seed: u8) -> String {
    status_id::new_note_id(ms, [seed; 10])
}

#[test]
fn a_status_id_is_always_the_same_width() {
    // The documented client recipe sorts by *length* before it sorts lexically.
    // Any variation here and the length clause starts deciding order.
    let mut widths = std::collections::BTreeSet::new();
    for (ms, seed) in [
        (0u64, 0u8),
        (1, 1),
        (1_724_000_000_000, 200),
        (u64::MAX >> 16, 255),
    ] {
        for owner in [owner(), Uuid::nil(), Uuid::max()] {
            let id = status_id::encode(&note_at(ms, seed), owner).expect("encode");
            widths.insert(id.len());
        }
    }
    assert_eq!(
        widths.len(),
        1,
        "status IDs vary in width: {widths:?} — the length clause would order them"
    );
    assert_eq!(*widths.iter().next().unwrap(), status_id::WIDTH);
}

#[test]
fn later_statuses_sort_lexically_later() {
    let earlier = status_id::encode(&note_at(1_000, 9), owner()).unwrap();
    let later = status_id::encode(&note_at(2_000, 1), owner()).unwrap();

    assert!(
        earlier < later,
        "chronological order must equal lexical order: {earlier} !< {later}"
    );
}

#[test]
fn the_documented_client_sort_recipe_agrees_with_chronology() {
    // Mastodon's own docs: "Sort by length. Newer statuses will have longer
    // IDs. Sort lexically." Run exactly that and check it reproduces the order
    // the server intended.
    let minted: Vec<String> = (1..=20)
        .map(|n| status_id::encode(&note_at(n * 1_000, n as u8), owner()).unwrap())
        .collect();

    let mut shuffled = minted.clone();
    shuffled.reverse();
    shuffled.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));

    assert_eq!(
        shuffled, minted,
        "the documented client sort must reproduce chronological order"
    );
}

#[test]
fn the_owner_never_affects_ordering() {
    // The fixed-width point, stated as the property it protects: a member with
    // a longer name — or any owner id at all — must not sort as newer.
    let earlier_note = note_at(1_000, 1);
    let later_note = note_at(2_000, 1);

    let earlier_by_max_owner = status_id::encode(&earlier_note, Uuid::max()).unwrap();
    let later_by_nil_owner = status_id::encode(&later_note, Uuid::nil()).unwrap();

    assert!(
        earlier_by_max_owner < later_by_nil_owner,
        "the owner half leaked into ordering"
    );
}

#[test]
fn an_id_carries_its_note_and_owner_home() {
    // The whole reason for the scheme: resolving an ID is a decode plus a
    // primary-key lookup, with no index and no new column (ADR 0005 R2).
    let note = note_at(1_724_000_000_000, 42);
    let id = status_id::encode(&note, owner()).unwrap();

    let (decoded_note, decoded_owner) = status_id::decode(&id).expect("decode");
    assert_eq!(decoded_note, note);
    assert_eq!(decoded_owner, owner());
}

#[test]
fn every_owner_round_trips_exactly() {
    // A UUID is 128 bits and base32 carries 130 in 26 characters. The two
    // padding bits must not corrupt the edges.
    for owner in [
        Uuid::nil(),
        Uuid::max(),
        owner(),
        Uuid::parse_str(OTHER_OWNER).unwrap(),
    ] {
        let id = status_id::encode(&note_at(1_000, 1), owner).unwrap();
        let (_, decoded) = status_id::decode(&id).expect("decode");
        assert_eq!(decoded, owner, "owner did not survive the round trip");
    }
}

#[test]
fn the_alphabet_has_no_ambiguous_characters() {
    // Crockford base32 drops I, L, O and U so an ID read aloud or retyped from
    // a screenshot cannot become a different one.
    let id = status_id::encode(&note_at(1_724_000_000_000, 7), owner()).unwrap();
    for c in id.chars() {
        assert!(
            c.is_ascii_digit() || c.is_ascii_uppercase(),
            "{c} is outside the alphabet"
        );
        assert!(
            !matches!(c, 'I' | 'L' | 'O' | 'U'),
            "{c} is ambiguous and must not appear"
        );
    }
}

#[test]
fn two_notes_in_the_same_millisecond_get_different_ids() {
    let a = status_id::new_note_id(1_724_000_000_000, [1; 10]);
    let b = status_id::new_note_id(1_724_000_000_000, [2; 10]);
    assert_ne!(a, b, "randomness must break ties within a millisecond");
}

#[test]
fn a_malformed_id_is_refused_rather_than_guessed() {
    // A status ID that half-parses would resolve to the wrong member's pod.
    let valid = status_id::encode(&note_at(1_000, 1), owner()).unwrap();

    for bad in [
        String::new(),
        "not-an-id".into(),
        valid[..valid.len() - 1].to_string(),
        format!("{valid}X"),
        // Lowercase is not the encoding we emit; accepting it invites two
        // spellings of the same id.
        valid.to_lowercase(),
        // Characters outside Crockford's alphabet.
        format!("{}IIII", &valid[..status_id::WIDTH - 4]),
    ] {
        assert!(
            status_id::decode(&bad).is_none(),
            "{bad:?} should not decode"
        );
    }
}

#[test]
fn a_note_id_is_refused_if_it_is_not_a_ulid() {
    // Phase 5 minted note IRIs with UUIDv4 local parts. Those are not sortable
    // and must not be silently accepted into an ID that claims to be.
    assert!(status_id::encode("not-a-ulid", owner()).is_none());
    assert!(status_id::encode(&Uuid::new_v4().to_string(), owner()).is_none());
    assert!(status_id::encode("", owner()).is_none());
}

#[test]
fn a_note_iri_is_reconstructed_from_the_id_alone() {
    let note = note_at(1_724_000_000_000, 3);
    let id = status_id::encode(&note, owner()).unwrap();

    let (decoded_note, _) = status_id::decode(&id).unwrap();
    assert_eq!(
        status_id::note_iri(&decoded_note, "alice", "brolly.test"),
        format!("https://alice.brolly.test/~/notes/{note}")
    );
}
