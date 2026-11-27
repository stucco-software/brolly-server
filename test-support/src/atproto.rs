//! Fixtures for ATProto writes that hold to their lexicons (stage 4a, H5).

use serde_json::{Value, json};

/// A fixed, valid `createdAt`.
pub const CREATED_AT: &str = "2026-01-01T00:00:00.000Z";

/// A valid `app.bsky.feed.post` with `text` (≤ 300 graphemes).
pub fn post(text: &str) -> Value {
    json!({"$type": "app.bsky.feed.post", "text": text, "createdAt": CREATED_AT})
}

/// The `n`th of a deterministic sequence of valid, increasing TIDs:
/// 13 base32-sortable characters, the first in `2–7a–j`.
pub fn tid(n: u64) -> String {
    const ALPHABET: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";
    let mut out = [b'2'; 13];
    if let Some(first) = out.first_mut() {
        *first = b'3';
    }
    let mut rest = n;
    for slot in out.iter_mut().skip(1).rev() {
        *slot = ALPHABET.get((rest % 32) as usize).copied().unwrap_or(b'2');
        rest /= 32;
    }
    out.iter().map(|&b| b as char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tids_are_valid_and_increase() {
        let a = tid(0);
        let b = tid(1);
        let c = tid(1_000_000);
        assert_eq!(a, "3222222222222");
        assert!(a < b && b < c);
        for t in [a, b, c] {
            assert!(atrium_like_tid(&t), "{t}");
        }
    }

    fn atrium_like_tid(t: &str) -> bool {
        t.len() == 13
            && t.starts_with(|c: char| "234567abcdefghij".contains(c))
            && t.chars()
                .all(|c| "234567abcdefghijklmnopqrstuvwxyz".contains(c))
    }
}
