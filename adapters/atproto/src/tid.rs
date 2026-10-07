//! TID revs: the mint, and the guarantee that a mint makes progress.
//!
//! A revision is a TID — 13 base32 characters, 64 bits, order-preserving — and
//! atrium-api owns the type (`types::string::Tid`). What atrium does not own is
//! the mint policy: `Tid::now` reads wall time alone, so a retry inside the
//! same millisecond, or a clock that stepped backwards, mints a TID that does
//! not clear the stored head — and the compare-and-set at the head would
//! refuse it forever (1, A).
//!
//! Monotonicity is enforced where the head moves, not at the mint (1, C); the
//! mint's only job is to be *able* to progress: strictly greater than the
//! floor it is handed, by the clock when the clock has moved, past it when it
//! has not.
//!
//! The bit arithmetic here is ours because it has to be — atrium parses and
//! validates the type but exposes no way to take one apart or put one together
//! at a chosen value. The vectors atrium's own tests pin (`0` encodes as
//! `"2222222222222"`, `1` as `"2222222222223"`) pin ours below.

use atrium_api::types::LimitedU32;

// Re-exported so the crates that handle revs — the server's handlers, the
// tests — use the type atrium defines without each depending on atrium-api.
pub use atrium_api::types::string::Tid;

/// The base32 alphabet of the TID encoding, most significant digit last in
/// this constant only because the encode walks from the bottom up.
const ALPHABET: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";

/// Mint a rev that clears `floor`, from the current clock.
pub fn mint_after(floor: &Tid) -> Tid {
    mint(&Tid::now(LimitedU32::MIN), floor)
}

/// Mint a rev that clears `floor`, given the wall-time candidate.
///
/// The candidate is a parameter rather than a clock read so the ordering
/// cases — a same-millisecond tie, a clock that stepped backwards — are
/// testable without sleeping and without a clock.
pub fn mint(now: &Tid, floor: &Tid) -> Tid {
    // Wall time wins when it has moved past the floor. Otherwise the floor
    // plus one: the low ten bits are the clock id, so the increment breaks a
    // same-millisecond tie in the clock-id bits, and a carry past them bumps
    // the timestamp past a clock that stepped backwards (1, A).
    from_bits(bits(now).max(bits(floor) + 1))
}

/// The 64 bits a TID encodes, as the numeric ordering key.
///
/// The encoding is order-preserving, so this equals the lexicographic order of
/// the text — which is why the head update can compare the stored text with
/// `<` and why the tests below assert the two orders agree (1, A).
fn bits(tid: &Tid) -> u128 {
    tid.as_str().bytes().fold(0u128, |acc, byte| {
        // Every byte of a `Tid` is in the alphabet — parsing validated it —
        // so the fallback is unreachable; it exists to keep the arithmetic
        // total rather than to be exercised.
        (acc << 5) | ALPHABET.iter().position(|&a| a == byte).unwrap_or(0) as u128
    })
}

/// The TID a 64-bit value encodes, saturating at the top of the space.
///
/// A value under 2^64 always encodes to a valid TID: the leading character is
/// at most 'j', which the grammar allows. A value at or above it cannot be a
/// TID at all — reachable only from a floor within 31 of the ceiling, a
/// timestamp no real clock produces — and saturates, so a mint past it fails
/// to clear the floor's rev and the compare-and-set refuses: a corrupt head
/// surfaces as a conflict instead of the revision wrapping backwards.
fn from_bits(value: u128) -> Tid {
    let mut out = [b'2'; 13];
    let mut rest = value.min(u64::MAX as u128) as u64;
    for slot in out.iter_mut().rev() {
        *slot = ALPHABET[(rest & 0x1f) as usize];
        rest >>= 5;
    }
    // Valid by construction for a capped value; the fallback is unreachable
    // and exists only because `Tid::new` answers with a Result.
    Tid::new(String::from_utf8_lossy(&out).into_owned())
        .unwrap_or_else(|_| Tid::now(LimitedU32::MIN))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vectors atrium-api's own tests pin, so our arithmetic cannot drift
    /// from its encoder without this failing.
    #[test]
    fn the_bit_layout_is_atriums() {
        assert_eq!(from_bits(0).as_str(), "2222222222222");
        assert_eq!(from_bits(1).as_str(), "2222222222223");
        assert_eq!(bits(&Tid::new("2222222222223".into()).unwrap()), 1);
    }

    #[test]
    fn a_same_millisecond_tie_breaks_in_the_clock_id() {
        // Two mints from the same wall time: the first clears the floor, the
        // second has to clear the first, and only the clock-id bits can move.
        let now = from_bits(0x0000_0100_0000_0000);
        let floor = now.clone();

        let first = mint(&now, &floor);
        assert!(
            first.as_str() > floor.as_str(),
            "the mint did not clear the floor: {} -> {}",
            floor.as_str(),
            first.as_str()
        );
        assert_eq!(
            bits(&first),
            bits(&floor) + 1,
            "the tie must break in the low bits"
        );

        let second = mint(&now, &first);
        assert!(
            second.as_str() > first.as_str(),
            "a remint in the same millisecond did not progress: {} -> {}",
            first.as_str(),
            second.as_str()
        );
    }

    #[test]
    fn a_clock_that_stepped_backwards_still_mints_forward() {
        // The wall-time candidate is behind the floor — the case the head's
        // `rev <` guard refuses. The mint must clear the floor anyway, so the
        // retry the guard invites can succeed (1, A).
        let floor = from_bits(0x0000_0200_0000_0000);
        let stepped_back = from_bits(0x0000_0100_0000_0000);

        let minted = mint(&stepped_back, &floor);
        assert!(
            minted.as_str() > floor.as_str(),
            "a remint after a clock step backwards did not clear the head: {} -> {}",
            floor.as_str(),
            minted.as_str()
        );
        assert_eq!(bits(&minted), bits(&floor) + 1);
    }

    #[test]
    fn wall_time_wins_when_it_has_moved() {
        let floor = from_bits(1);
        let now = from_bits(0x0000_0300_0000_0000);

        assert_eq!(mint(&now, &floor), now);
    }

    #[test]
    fn lexicographic_order_is_numeric_order() {
        // The property the storage leans on: the text can be compared as text
        // (the head update's `rev <`, the migration's maxima) because that is
        // the numeric order of the TID (1, A). A corpus of values across the
        // range, sorted both ways, must agree.
        let mut corpus: Vec<u128> = (0..200u128).map(|n| n * 0x0100_0000_0000).collect();
        // A cheap deterministic scramble so the corpus is not a ramp.
        let mut x: u128 = 0x9e37_79b9_7f4a_7c15;
        for slot in corpus.iter_mut() {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *slot = (*slot ^ x) & ((1u128 << 64) - 1);
        }
        corpus.push(0);
        corpus.push((1u128 << 64) - 1);

        let mut by_bits: Vec<Tid> = corpus.iter().map(|v| from_bits(*v)).collect();
        let mut by_text = by_bits.clone();
        by_bits.sort_by_key(bits);
        by_text.sort_by(|a, b| a.as_str().cmp(b.as_str()));

        let texts: Vec<&str> = by_bits.iter().map(Tid::as_str).collect();
        let sorted: Vec<&str> = by_text.iter().map(Tid::as_str).collect();
        assert_eq!(texts, sorted, "text order disagreed with numeric order");

        // Everything the arithmetic produces is a TID atrium accepts.
        for tid in by_text {
            assert!(
                Tid::new(tid.to_string()).is_ok(),
                "{} is not a valid TID",
                tid.as_str()
            );
        }
    }

    #[test]
    fn a_mint_from_the_clock_always_clears_the_floor() {
        let floor = from_bits(0x0000_0400_0000_0000);
        let minted = mint_after(&floor);
        assert!(
            minted.as_str() > floor.as_str(),
            "a clock mint did not clear the floor: {} -> {}",
            floor.as_str(),
            minted.as_str()
        );
    }
}
