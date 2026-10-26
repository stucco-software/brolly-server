# Member Quotas Implementation Plan

<!-- doc-paths: skip -->
<!-- The plan names the migration and functions it creates, so not every
     path it cites resolves until it's implemented. -->

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An admin sets a per-member pod quota from the console or `brolly-admin`; the writes enforce it; the member sees usage against it.

**Architecture:** The override is a nullable `BIGINT` on `users`, read off the `User` row every pod write already loads (`User::quota(default)` is the one place override and default combine). Sizes are parsed and printed by one pair in `brolly-domain`. The console's member list reads the quota off `UserRow` in its one query; the CLI reads provenance by a second small query. Four chunks, each a deployable commit on `main`.

**Tech Stack:** Rust, axum 0.8, askama, sqlx 0.8 (Postgres, `time` feature), `time` 0.3. Tests: `cargo test`, which provisions Postgres via testcontainers (Docker must be running).

**Spec:** `docs/specs/2026-10-26-member-quotas.md` — read it first; every H-number below refers to it.

**House rules that bite here:**
- Library crates deny `unwrap`/`expect`/`panic`/`println!` (workspace clippy lints). Integration test files opt out with `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` at the top (already present in every file this plan touches); a library crate's in-file `mod tests` is covered by the crate-level `#![cfg_attr(test, allow(…))]` in its `lib.rs` — do not add a second attribute. `server/src/bin/admin.rs` lifts `print_stdout` and `print_stderr`, and nothing else does.
- No HTML via `format!`; one stylesheet; no literal colours outside `tokens.css`; every page one `h1`; every form control labelled. `server/tests/ui_invariants.rs` enforces the mechanical ones.
- Trunk-based: commit straight to `main`, one commit per chunk, every commit green. There is no git remote; do not try to push.
- Pre-commit (lefthook) runs `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `./tools/check-doc-paths.sh`. Run them yourself before `git commit` so the hook is a formality.
- **The working tree holds uncommitted theme work** (`theme_css` in `lib.rs`, `main.rs`, two templates, and every test's `AppState` literal). Leave it alone: never `git add -A`, `git add .`, `git stash`, or `git checkout --` a file. Stage only the files each task names. **A theme hunk must never ride into a commit:** `theme_css` is not a field of `AppState` at `HEAD`, so a commit carrying `theme_css: false,` in a test literal — or the field in `lib.rs` without `main.rs` — does not build on its own, and every commit must. `git add -p` is not available (non-interactive); instead build a theme-free patch for each such file and stage it with `git apply --cached`: `git diff -- <file> > /tmp/<file>.patch`, delete the `theme_css` hunks from the patch, `git apply --cached --check /tmp/<file>.patch && git apply --cached /tmp/<file>.patch`. The working tree keeps the theme lines. After committing, `git show HEAD | grep -c theme_css` must print 0 and `git diff | grep -c theme_css` must be what it was before.
- Gate shell chains on cargo's own exit status: `cargo test … > /tmp/x.log 2>&1 && …`, never `cargo test … | grep … && …` (the pipeline's status is `grep`'s).
- Commit messages: conventional prefix, a body that says why, and the trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.

---

## Chunk 1: The number

### Task 1.1: Sizes — `parse_size` and `format_size` (H2)

**Files:**
- Modify: `domain/src/media.rs` (append after `DEFAULT_POD_QUOTA_BYTES`; tests go in the existing `#[cfg(test)] mod tests` at the bottom)

- [ ] **Step 1: Write the failing tests**

Append inside `mod tests` in `domain/src/media.rs`:

```rust
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
        // A fraction of a byte is nothing.
        assert_eq!(parse_size("1.5"), Err(SizeError::NotANumber));
        assert_eq!(parse_size("5X"), Err(SizeError::UnknownUnit("x".into())));
        assert_eq!(parse_size("5 bytes"), Err(SizeError::UnknownUnit("bytes".into())));
        // The column is BIGINT: nothing above i64::MAX is a quota.
        assert_eq!(parse_size("99999999999G"), Err(SizeError::TooLarge));
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
            assert_eq!(parse_size(&format_size(bytes)), Ok(bytes), "exact round trip");
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p brolly-domain --lib -- media::tests 2>&1 | tail -20`
Expected: compile errors — `cannot find function parse_size`, `format_size`, `SizeError`.

- [ ] **Step 3: Implement**

Append to `domain/src/media.rs` after `DEFAULT_POD_QUOTA_BYTES` (before `is_allowed_media_type`):

```rust
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

/// The binary units a size may name, and their byte counts.
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
    let unit = unit.trim().to_ascii_lowercase();
    let multiplier = match unit.as_str() {
        "" | "b" => 1u64,
        "k" | "kb" | "kib" => 1 << 10,
        "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        "t" | "tb" | "tib" => 1 << 40,
        other => return Err(SizeError::UnknownUnit(other.to_string())),
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
    let whole: u128 = whole.parse().map_err(|_| SizeError::NotANumber)?;
    // Up to eighteen fractional digits are exact in u128; more cannot
    // change a byte count at any unit this grammar names.
    let fraction = fraction.unwrap_or("");
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
/// `1.5 GiB`, `412.5 MiB`, `1023.9 MiB`, `1023 B`, `0 B`. Always a string
/// `parse_size` accepts, and never more than the value it was given: rounding
/// to nearest would print `1024.0 MiB` for a byte under a gibibyte and
/// `8388608.0 TiB` for `i64::MAX` — which parses as too large, so a value
/// the console displayed would be refused on an untouched save.
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p brolly-domain --lib -- media::tests 2>&1 | tail -12`
Expected: all `media::tests` pass, including the five new ones. If `a_fraction_rounds_down_to_a_whole_byte` fails, check the fraction arithmetic is integer (`u128`), not float. If the round-trip test fails on `i64::MAX`, `format_size` is rounding to nearest instead of down.

- [ ] **Step 5: Lints**

Run: `cargo fmt --all && cargo clippy -p brolly-domain --all-targets -- -D warnings`
Expected: clean. Two things clippy on this toolchain (1.90) is known to want here, both already in the code above: `bytes.is_multiple_of(*unit)` rather than `bytes % unit == 0` (`manual_is_multiple_of`), and the `as u64` cast only after the `i64::MAX` check. If anything else fires, fix it rather than allow it.

### Task 1.2: The column, `User::quota`, the column list, `set_quota`, `quota_provenance` (H1)

**Files:**
- Create: `migrations/20261026000002_identity_user_quotas.sql`
- Modify: `identity/src/db.rs` — `User` struct (~line 52), `impl User` (~70), `create_user`'s `RETURNING` (~121), `find_by_username` (~150), `find_by_id` (~164), `find_by_email` (~190), `user_for_session` (~280); new functions after `set_role` (~500)
- Test: `identity/tests/persistence.rs`

- [ ] **Step 1: Write the migration**

```sql
-- A member's quota: an admin's override, or NULL for the instance default
-- (BROLLY_POD_QUOTA_BYTES). Who set it and when ride alongside, so the
-- console can say so; the setter is the admin acting through the console,
-- NULL when brolly-admin did it. ON DELETE SET NULL: deleting an admin does
-- not delete the fact that a quota was set. The CHECKs say what set_quota
-- guarantees: no negative quota, and a date exactly when there is a quota.
ALTER TABLE users
    ADD COLUMN quota_bytes  BIGINT      NULL,
    ADD COLUMN quota_set_at TIMESTAMPTZ NULL,
    ADD COLUMN quota_set_by UUID        NULL REFERENCES users(id) ON DELETE SET NULL,
    ADD CONSTRAINT users_quota_bytes_nonnegative
        CHECK (quota_bytes IS NULL OR quota_bytes >= 0),
    ADD CONSTRAINT users_quota_set_at_with_quota
        CHECK ((quota_bytes IS NULL) = (quota_set_at IS NULL));
```

- [ ] **Step 2: Write the failing tests**

Append to `identity/tests/persistence.rs`:

```rust
// --- quotas -----------------------------------------------------------------

#[tokio::test]
async fn a_quota_override_round_trips_and_clears() {
    let (_db, pool) = fresh().await;
    let alice = db::create_user(&pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    assert_eq!(alice.quota_bytes, None, "a new member has no override");
    assert_eq!(alice.quota(1 << 30), 1 << 30, "so the default applies");

    db::set_quota(&pool, alice.id, Some(5 << 30), None)
        .await
        .unwrap();
    let alice = db::find_by_username(&pool, "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alice.quota_bytes, Some(5 << 30));
    assert_eq!(alice.quota(1 << 30), 5 << 30, "the override wins");

    // Every path that loads a User carries it.
    assert_eq!(
        db::find_by_id(&pool, alice.id).await.unwrap().unwrap().quota_bytes,
        Some(5 << 30)
    );
    let token = db::create_session(&pool, alice.id, time::Duration::hours(1), None)
        .await
        .unwrap();
    assert_eq!(
        db::user_for_session(&pool, &token)
            .await
            .unwrap()
            .unwrap()
            .quota_bytes,
        Some(5 << 30)
    );

    db::set_quota(&pool, alice.id, None, None).await.unwrap();
    let alice = db::find_by_username(&pool, "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alice.quota_bytes, None, "cleared");
    assert_eq!(alice.quota(1 << 30), 1 << 30);
}

#[tokio::test]
async fn provenance_names_the_console_admin_and_not_the_cli() {
    let (_db, pool) = fresh().await;
    let alice = db::create_user(&pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let keeper = db::create_user(&pool, "keeper", None, "correct-horse-battery", "admin")
        .await
        .unwrap();

    assert!(
        db::quota_provenance(&pool, alice.id)
            .await
            .unwrap()
            .is_none(),
        "no override, no provenance"
    );

    db::set_quota(&pool, alice.id, Some(5 << 30), Some(keeper.id))
        .await
        .unwrap();
    let by_console = db::quota_provenance(&pool, alice.id)
        .await
        .unwrap()
        .expect("set");
    assert_eq!(by_console.set_by.as_deref(), Some("keeper"));

    db::set_quota(&pool, alice.id, Some(6 << 30), None)
        .await
        .unwrap();
    let by_cli = db::quota_provenance(&pool, alice.id)
        .await
        .unwrap()
        .expect("set");
    assert_eq!(by_cli.set_by, None, "the CLI is the database, not a person");
    assert!(by_cli.set_at >= by_console.set_at);
}

#[tokio::test]
async fn deleting_the_admin_keeps_the_quota_and_loses_the_name() {
    let (_db, pool) = fresh().await;
    let alice = db::create_user(&pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let keeper = db::create_user(&pool, "keeper", None, "correct-horse-battery", "admin")
        .await
        .unwrap();
    db::set_quota(&pool, alice.id, Some(5 << 30), Some(keeper.id))
        .await
        .unwrap();

    db::delete_user(&pool, keeper.id).await.unwrap();

    let alice = db::find_by_username(&pool, "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alice.quota_bytes, Some(5 << 30), "ON DELETE SET NULL, not CASCADE");
    let provenance = db::quota_provenance(&pool, alice.id)
        .await
        .unwrap()
        .expect("still set");
    assert_eq!(provenance.set_by, None);
}

#[tokio::test]
async fn a_negative_quota_cannot_be_stored() {
    let (_db, pool) = fresh().await;
    let alice = db::create_user(&pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    assert!(
        db::set_quota(&pool, alice.id, Some(-1), None).await.is_err(),
        "the CHECK refuses it; set_quota does not pretend otherwise"
    );
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p brolly-identity --test persistence -- quota 2>&1 | tail -20`
Expected: compile errors — no field `quota_bytes`, no method `quota`, no `set_quota`, no `quota_provenance`.

- [ ] **Step 4: Implement in `identity/src/db.rs`**

(a) The struct and method. Replace the `User` struct and extend `impl User`:

```rust
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub did_plc: Option<String>,
    pub role: String,
    pub status: String,
    /// An admin's quota override in bytes, or `None` for the instance default.
    /// Combined with the default by [`User::quota`] and nowhere else.
    pub quota_bytes: Option<i64>,
}

impl User {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }
    /// The member's quota: an admin's override if there is one, else the
    /// instance default. The only place the two are combined. A stored
    /// value is never negative (the column's `CHECK`); the conversion
    /// saturates at zero regardless, so this is total.
    pub fn quota(&self, instance_default: u64) -> u64 {
        match self.quota_bytes {
            Some(bytes) => u64::try_from(bytes).unwrap_or(0),
            None => instance_default,
        }
    }
}

/// The columns a `User` is read from, in `FromRow` order. One list, used by
/// every query that produces a `User`: a fifth hand-written copy is how one
/// gets missed, and sqlx reports a missing column at runtime, per query.
const USER_COLUMNS: [&str; 8] = [
    "id",
    "username",
    "email",
    "email_verified",
    "did_plc",
    "role",
    "status",
    "quota_bytes",
];

/// `USER_COLUMNS` joined for a `SELECT`, each prefixed (`"u."` for a join,
/// `""` for a bare table).
fn user_columns(prefix: &str) -> String {
    USER_COLUMNS
        .iter()
        .map(|c| format!("{prefix}{c}"))
        .collect::<Vec<_>>()
        .join(", ")
}
```

(b) Every query that produces a `User`. In `create_user`, replace the SQL string with:

```rust
    let sql = format!(
        "INSERT INTO users (id, username, email, password_hash, role)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING {}",
        user_columns("")
    );
    sqlx::query_as::<_, User>(&sql)
```

(leave the `.bind`s and the `map_err` exactly as they are). In `find_by_username`, `find_by_id`, `find_by_email`:

```rust
    let sql = format!("SELECT {} FROM users WHERE username = $1", user_columns(""));
    Ok(sqlx::query_as::<_, User>(&sql)
```

(with `WHERE id = $1` and `WHERE email = $1` respectively). In `user_for_session`:

```rust
    let sql = format!(
        "SELECT {} FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = $1 AND s.expires_at > now() AND u.status = 'active'",
        user_columns("u.")
    );
    Ok(sqlx::query_as::<_, User>(&sql)
```

Then grep: `grep -n email_verified identity/src/db.rs` must match only the `USER_COLUMNS` entry — `email_verified` is a column only a `User` carries, so any other hit is a query that still lists the user columns by hand (prefixed or not) and must use `user_columns`. (`list_users` lists *its* columns by hand too, but it produces a `UserRow`, not a `User`; it is Chunk 3's.)

(c) The two store functions, after `set_role`:

```rust
/// Set or clear a member's quota override. `None` clears it. `set_by` is
/// the admin acting through the console, `None` for the CLI — the CLI is
/// the database, not a person. One statement either way, so the three
/// columns can never disagree; a negative value is refused by the column's
/// `CHECK` and comes back as the database error it is.
pub async fn set_quota(
    pool: &PgPool,
    user_id: Uuid,
    quota_bytes: Option<i64>,
    set_by: Option<Uuid>,
) -> Result<(), DbError> {
    match quota_bytes {
        Some(bytes) => {
            sqlx::query(
                "UPDATE users
                    SET quota_bytes = $2, quota_set_at = now(), quota_set_by = $3
                  WHERE id = $1",
            )
            .bind(user_id)
            .bind(bytes)
            .bind(set_by)
            .execute(pool)
            .await?;
        }
        None => {
            sqlx::query(
                "UPDATE users
                    SET quota_bytes = NULL, quota_set_at = NULL, quota_set_by = NULL
                  WHERE id = $1",
            )
            .bind(user_id)
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

/// Who set a member's quota override and when: the CLI's readback, since
/// `User` carries the number but not the provenance. (The console reads the
/// same facts off `UserRow` instead, one query for the whole list.)
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct QuotaProvenance {
    pub set_at: time::OffsetDateTime,
    /// The setter's username; `None` when the CLI set it, or when the admin
    /// who did has since been deleted.
    pub set_by: Option<String>,
}

/// `None` when the member has no override.
pub async fn quota_provenance(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Option<QuotaProvenance>, DbError> {
    Ok(sqlx::query_as::<_, QuotaProvenance>(
        "SELECT u.quota_set_at AS set_at, s.username AS set_by
           FROM users u LEFT JOIN users s ON s.id = u.quota_set_by
          WHERE u.id = $1 AND u.quota_bytes IS NOT NULL",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?)
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p brolly-identity --test persistence 2>&1 | tail -8`
Expected: every test in the file passes (the pre-existing ones prove nothing else broke on the column list). Then the whole identity crate: `cargo test -p brolly-identity 2>&1 | grep "test result"` — all ok.

- [ ] **Step 6: Run the server's test binaries that construct users**

`cargo test -p brolly-server --test auth_flow --test dashboard --test admin > /tmp/q.log 2>&1; grep -E "test result|FAILED" /tmp/q.log`
Expected: all ok. A failure mentioning `quota_bytes` means a `User` query was missed in step 4(b).

### Task 1.3: Enforcement reads the row (H3)

**Files:**
- Modify: `server/src/pod.rs:203-211` (`within_quota`), the three call sites (`put`, `post`, `patch`), `server/src/mastodon_api.rs:572`
- Test: `server/tests/pod_http.rs`, `server/tests/mastodon_compose.rs`

- [ ] **Step 1: Write the failing tests**

In `server/tests/pod_http.rs`, after `a_pod_refuses_a_write_past_its_quota`:

```rust
/// An admin's override is the member's quota, not the instance's number.
/// Set directly in the database here — the console and the CLI are later
/// chunks — and read by the write path off the row it already loads.
#[tokio::test]
async fn a_members_own_quota_overrides_the_instance_default() {
    let h = harness_sized(brolly_domain::media::MAX_UPLOAD_BYTES, 2 * 1024 * 1024).await;
    db::set_quota(&h._db.pool, h.user, Some(4 * 1024 * 1024), None)
        .await
        .unwrap();
    let mebibyte = "x".repeat(1024 * 1024);

    // Three mebibytes fit under four where the instance default is two.
    for name in ["one", "two", "three"] {
        let (status, body, _) = h
            .send(
                "PUT",
                &format!("/~/{name}.pdf"),
                Some(("application/pdf", &mebibyte)),
                true,
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{name}: {body}");
    }

    // Lowered below what the pod holds: an add is refused, a delete is not,
    // and the delete is how the member gets back under.
    db::set_quota(&h._db.pool, h.user, Some(1024 * 1024), None)
        .await
        .unwrap();
    let (status, _, _) = h
        .send("PUT", "/~/four.pdf", Some(("application/pdf", &mebibyte)), true)
        .await;
    assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);
    let (status, _, _) = h.send("DELETE", "/~/one.pdf", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "a delete always runs");
}
```

In `server/tests/mastodon_compose.rs`, after `an_upload_past_the_pods_quota_is_refused`:

```rust
/// The upload honours a member's override the way a Solid write does.
#[tokio::test]
async fn an_upload_honours_the_members_own_quota() {
    let h = harness_sized(brolly_domain::media::MAX_UPLOAD_BYTES, 2 * 1024 * 1024).await;
    let (user, token) = a_member(&h, "alice").await;
    db::set_quota(&h.db.pool, user, Some(4 * 1024 * 1024), None)
        .await
        .unwrap();
    let boundary = "----brollytest";
    let big = || {
        let mut body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\n\
             Content-Type: image/png\r\n\r\n"
        );
        body.push_str(&"x".repeat(1024 * 1024));
        body.push_str(&format!("\r\n--{boundary}--\r\n"));
        Request::builder()
            .method("POST")
            .uri("/api/v1/media")
            .header(header::HOST, BASE)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap()
    };

    // Two mebibytes would have been one too many under the instance default.
    let first = send(&h, big()).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    let second = send(&h, big()).await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.body);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p brolly-server --test pod_http -- a_members_own_quota 2>&1 | grep -E "^test|left|right"` and the same for `--test mastodon_compose -- an_upload_honours`.
Expected: both FAIL — under the 2 MiB default the *second* pod PUT (`two`) is already 507 (`left: 507, right: 201`; the store's floor plus one mebibyte fits, plus another does not — exactly what `a_pod_refuses_a_write_past_its_quota` shows), and the second upload is 507 (`left: 507, right: 200`). The instance default still governs. Margin to know about: three mebibytes under a 4 MiB override leaves the store floor plus WAL growth under one mebibyte, which the existing test already relies on; if it ever flakes, `5 * 1024 * 1024` is the dial.

- [ ] **Step 3: Implement**

In `server/src/pod.rs`, replace `within_quota`:

```rust
/// Does the pod have room for `incoming` more bytes under its quota?
///
/// The quota is the member's: an admin's override if one is set, else the
/// instance default — `User::quota` decides, and the row is the one every
/// write handler already loaded, so this costs no query. Measured, not
/// tracked: the pod's directory on disk — store and blobs together — is
/// the one number that cannot drift from what the member actually holds,
/// and a write that frees space makes room again without bookkeeping.
/// Conservative on a replace: the incoming bytes count in full even where
/// they displace old ones.
///
/// Fails open. A pod whose size cannot be read is an operational fault to
/// log loudly, not a reason to refuse a member their own write — the quota
/// bounds what one grant can cost the instance; it is not the thing that
/// keeps the instance up.
pub(crate) fn within_quota(state: &AppState, user: &User, incoming: usize) -> bool {
    match state.stores.pod_bytes(user.id) {
        Ok(used) => used.saturating_add(incoming as u64) <= user.quota(state.pod_quota_bytes),
        Err(e) => {
            tracing::error!(error = %e, user = %user.id, "could not measure the pod for its quota");
            true
        }
    }
}
```

Change the three call sites in `pod.rs` from `within_quota(&state, request.user.id, body.len())` to `within_quota(&state, &request.user, body.len())`, and the one in `mastodon_api.rs` from `crate::pod::within_quota(&state, user.id, bytes.len())` to `crate::pod::within_quota(&state, &user, bytes.len())`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p brolly-server --test pod_http --test mastodon_compose > /tmp/q.log 2>&1; grep -E "test result|FAILED" /tmp/q.log`
Expected: both suites ok (the quota tests from `76e508f` still pass — the default still applies to a member with no override).

### Task 1.4: Lints, docs line, commit

- [ ] **Step 1: Deploy doc**

In `docs/deploying.md`, in the `BROLLY_POD_QUOTA_BYTES` row of the configuration table, append to the Notes cell: ` The default; an admin can set a different quota per member (`brolly-admin quota`, or the console).`

- [ ] **Step 2: Gates**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings > /tmp/c.log 2>&1 && ./tools/check-doc-paths.sh; grep -E "^(warning|error)" -A4 /tmp/c.log`
Expected: `doc paths ok` printed (it only runs if clippy passed) and no clippy output.

- [ ] **Step 3: Commit**

```bash
git add migrations/20261026000002_identity_user_quotas.sql identity/src/db.rs identity/tests/persistence.rs domain/src/media.rs server/src/pod.rs server/src/mastodon_api.rs server/tests/pod_http.rs server/tests/mastodon_compose.rs docs/deploying.md
git commit -F - <<'EOF'
feat(identity): a member's quota is their own (quotas 1: the number)

76e508f gave every pod the instance's one number. The member who hosts
the community's photo archive needs more, and the only way to give it
to them was to raise the ceiling for everybody and redeploy.

users gains quota_bytes — NULL for the instance default — with who set
it and when alongside, under two CHECKs that say what set_quota
guarantees. User::quota(default) is the one place override and default
combine, and within_quota asks it off the row every write handler
already loaded, so enforcement costs no query. The four SELECTs and the
RETURNING that produce a User now share one column list: a fifth
hand-written copy is how one gets missed, and the first draft of the
spec missed find_by_id.

Sizes are parsed and printed by one pair in brolly-domain — "5G",
"512 MiB", "1.5G", plain bytes — so the console, the CLI and the member
overview agree on what a number looks like, and every string the
formatter prints parses back.

The surfaces that set the number are the next three chunks.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
EOF
```

`server/tests/pod_http.rs` and `server/tests/mastodon_compose.rs` carry the operator's `theme_css` line: stage them theme-free with `git apply --cached` as the preamble describes.

---

## Chunk 2: The CLI

### Task 2.1: `brolly-admin quota` (H5)

**Files:**
- Modify: `server/src/bin/admin.rs` — `USAGE`, the `match command`, a new `quota` function after `set_role`
- Modify: `docs/deploying.md` — the "Afterwards" list

There is no CLI test harness (spec, Non-goals); the verb is thin over `db::set_quota`/`quota_provenance`/`parse_size`, all tested in chunk 1. Verify by running it against the compose stack at the end.

- [ ] **Step 1: USAGE**

In `USAGE`, after the `whoami` line in the USAGE block add:

```
    brolly-admin quota <username> [<size>|default]
```

In COMMANDS, after `whoami`'s entry:

```
    quota        Print a member's quota, or set it: a size like 5G, 512M
                 or 1.5G (binary units; plain digits are bytes), or the
                 word default to clear the override. The instance default
                 is BROLLY_POD_QUOTA_BYTES, read here as the server reads it.
```

In ENVIRONMENT, after `BROLLY_DATA_DIR`:

```
    BROLLY_POD_QUOTA_BYTES  quota only; the instance default, as the server reads it
```

`BROLLY_POD_QUOTA_BYTES` is 22 characters, the width of the existing gutter,
so re-align the three existing ENVIRONMENT entries to a 24-column gutter
(two more spaces each) rather than leave one ragged line.

- [ ] **Step 2: Dispatch**

In `match command`, after the `"whoami"` arm:

```rust
        "quota" => quota(&pool, &args).await,
```

- [ ] **Step 3: The verb**

After `set_role` (before `plc_retry`):

```rust
/// `quota <username>` prints; `quota <username> <size>` sets; `quota
/// <username> default` clears. The CLI is the database, not a person, so
/// the setter is recorded as nobody. The instance default is read as the
/// server reads it, so the readback names the number the writes use.
async fn quota(pool: &sqlx::PgPool, args: &[String]) -> ExitCode {
    let Some(username) = args.get(1) else {
        eprintln!("usage: brolly-admin quota <username> [<size>|default]");
        return ExitCode::FAILURE;
    };
    let user = match brolly_identity::db::find_by_username(pool, username).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            eprintln!("no such member: {username}");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("lookup failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    enum Change {
        Print,
        Clear,
        Set(i64),
    }
    let change = match args.get(2).map(String::as_str) {
        None => Change::Print,
        Some("default") => Change::Clear,
        Some(size) => match brolly_domain::media::parse_size(size) {
            Ok(bytes) => Change::Set(i64::try_from(bytes).unwrap_or(i64::MAX)),
            Err(e) => {
                eprintln!("{size}: {e}");
                return ExitCode::FAILURE;
            }
        },
    };
    let quota_bytes = match change {
        Change::Print => None,
        Change::Clear => Some(None),
        Change::Set(bytes) => Some(Some(bytes)),
    };
    if let Some(quota_bytes) = quota_bytes
        && let Err(e) = brolly_identity::db::set_quota(pool, user.id, quota_bytes, None).await
    {
        eprintln!("could not set the quota: {e}");
        return ExitCode::FAILURE;
    }

    // Read back rather than echo: what is printed is what is stored.
    let instance_default = std::env::var("BROLLY_POD_QUOTA_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(brolly_domain::media::DEFAULT_POD_QUOTA_BYTES);
    let (user, provenance) = match (
        brolly_identity::db::find_by_username(pool, username).await,
        brolly_identity::db::quota_provenance(pool, user.id).await,
    ) {
        (Ok(Some(user)), Ok(provenance)) => (user, provenance),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("readback failed: {e}");
            return ExitCode::FAILURE;
        }
        (Ok(None), _) => {
            eprintln!("no such member: {username}");
            return ExitCode::FAILURE;
        }
    };
    let origin = match provenance {
        Some(p) => format!("set {}", p.set_at.date()),
        None => "instance default".to_string(),
    };
    println!(
        "@{username}: {} ({origin})",
        brolly_domain::media::format_size(user.quota(instance_default))
    );
    ExitCode::SUCCESS
}
```

`brolly_domain` is already a dependency of `brolly-server` (the bin is in that crate). The `if let … && let` chain is a Rust 2024 let-chain, which this workspace already uses (`server/src/auth.rs:685`, the same shape).

- [ ] **Step 4: Build and lint**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings > /tmp/c.log 2>&1; grep -E "^(warning|error)" -A4 /tmp/c.log`
Expected: clean.

- [ ] **Step 5: Run it for real**

With the compose stack up (`docker compose up -d postgres`; `DATABASE_URL=postgres://postgres:postgres@localhost:5544/brolly`). **Migrations run in the server's `main`, not in `brolly-admin`**, so start the server once against that `DATABASE_URL` after chunk 1 (`cargo run --bin brolly-server`, then stop it) or the verb fails with `column "quota_bytes" does not exist` — a stale database, not a chunk 1 bug. A member `alice` must exist (register one through the app, or `brolly-admin whoami alice` to confirm), and `BROLLY_POD_QUOTA_BYTES` must be unset in the shell for the `1 GiB` lines below:

```
cargo run -q --bin brolly-admin -- quota alice
cargo run -q --bin brolly-admin -- quota alice 5G
cargo run -q --bin brolly-admin -- quota alice
cargo run -q --bin brolly-admin -- quota alice 5X
cargo run -q --bin brolly-admin -- quota alice default
cargo run -q --bin brolly-admin -- quota alice
```

Expected, line by line: `@alice: 1 GiB (instance default)`; `@alice: 5 GiB (set 2026-10-26)`; the same; `5X: x is not a unit; use K, M, G or T (binary)` and exit 1; `@alice: 1 GiB (instance default)`; the same. If no stack is available, skip this step and say so in the commit body.

- [ ] **Step 6: Deploy doc and commit**

In `docs/deploying.md`'s "Afterwards" fenced block, after the `demote` line:

```
brolly-admin quota <username> 5G        # a member's own quota; `default` clears it
```

```bash
git add server/src/bin/admin.rs docs/deploying.md
git commit -F - <<'EOF'
feat(admin): brolly-admin quota (quotas 2: the CLI)

quota <username> prints a member's effective quota and whether it is an
override; quota <username> <size> sets one; quota <username> default
clears it. Sizes are the one grammar from brolly-domain. The CLI is the
database, not a person, so the setter is recorded as nobody. The verb
reads back rather than echoes, so what it prints is what is stored, and
it reads the instance default as the server does, so the number it names
is the number the writes use.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
EOF
```

---

## Chunk 3: The console

### Task 3.1: The row carries the quota (H1, H4)

**Files:**
- Modify: `identity/src/db.rs` — `UserRow` (~line 514) and `list_users` (~529)
- Test: `identity/tests/persistence.rs`

- [ ] **Step 1: Write the failing test**

Append to `identity/tests/persistence.rs`:

```rust
#[tokio::test]
async fn the_member_list_carries_each_quota_and_who_set_it() {
    let (_db, pool) = fresh().await;
    let alice = db::create_user(&pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let bob = db::create_user(&pool, "bob", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let keeper = db::create_user(&pool, "keeper", None, "correct-horse-battery", "admin")
        .await
        .unwrap();
    db::set_quota(&pool, alice.id, Some(5 << 30), Some(keeper.id))
        .await
        .unwrap();
    db::set_quota(&pool, bob.id, Some(2 << 30), None)
        .await
        .unwrap();

    let rows = db::list_users(&pool).await.unwrap();
    let row = |name: &str| rows.iter().find(|r| r.username == name).unwrap();

    assert_eq!(row("alice").quota_bytes, Some(5 << 30));
    assert_eq!(row("alice").quota_set_by.as_deref(), Some("keeper"));
    assert!(row("alice").quota_set_at.is_some());

    assert_eq!(row("bob").quota_bytes, Some(2 << 30));
    assert_eq!(row("bob").quota_set_by, None, "CLI-set: no name");
    assert!(row("bob").quota_set_at.is_some());

    assert_eq!(row("keeper").quota_bytes, None);
    assert_eq!(row("keeper").quota_set_by, None);
    assert_eq!(row("keeper").quota_set_at, None);
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p brolly-identity --test persistence -- the_member_list 2>&1 | tail -6`
Expected: compile error — no field `quota_bytes` on `UserRow`.

- [ ] **Step 3: Implement**

Replace `UserRow` and `list_users` in `identity/src/db.rs`:

```rust
/// One row of the admin user list (ADR 0005, R5).
///
/// Postgres answers this alone. `display_name` is deliberately absent: it
/// lives in each member's pod, and opening one *store* per row to render a
/// table is the exact mistake ADR 0005 exists to prevent. (Measuring a pod's
/// directory on disk is not that: no store is opened, no LRU slot taken,
/// which is why the console may show usage per row.) It arrives with the
/// actor index.
///
/// The quota and its provenance ride here so the console's list is one
/// query however many members: the setter's name is a self-join on `users`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub username: String,
    pub role: String,
    pub status: String,
    pub did_plc: Option<String>,
    pub created_at: time::OffsetDateTime,
    /// An admin's override, or `None` for the instance default.
    pub quota_bytes: Option<i64>,
    pub quota_set_at: Option<time::OffsetDateTime>,
    /// The setter's username; `None` when the CLI set it, when the admin has
    /// since been deleted, or when there is no override.
    pub quota_set_by: Option<String>,
}

/// Every account, newest first.
///
/// Unpaginated, and that is a decision with a shelf life: it is correct for the
/// instance sizes this serves today and wrong for a large one. The list is
/// pointers only, so the fix is a LIMIT and a cursor rather than a new store.
pub async fn list_users(pool: &PgPool) -> Result<Vec<UserRow>, DbError> {
    Ok(sqlx::query_as::<_, UserRow>(
        "SELECT u.id, u.username, u.role, u.status, u.did_plc, u.created_at,
                u.quota_bytes, u.quota_set_at, s.username AS quota_set_by
           FROM users u LEFT JOIN users s ON s.id = u.quota_set_by
          ORDER BY u.created_at DESC",
    )
    .fetch_all(pool)
    .await?)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p brolly-identity --test persistence 2>&1 | tail -4`
Expected: ok.

### Task 3.2: A prefix entry in `SAME_ORIGIN_FORMS`, and the invariant learns it (H4)

**Files:**
- Modify: `server/src/lib.rs` — `SAME_ORIGIN_FORMS` (~line 409) and `same_origin` (~445)
- Test: `server/src/lib.rs` (a unit test in a new `#[cfg(test)] mod` at the bottom of the file), `server/tests/ui_invariants.rs`

- [ ] **Step 1: Write the failing unit test**

At the bottom of `server/src/lib.rs` (there is no test module in the file; add this one):

```rust
#[cfg(test)]
mod same_origin_tests {
    use super::*;

    #[test]
    fn a_listed_prefix_covers_the_paths_under_it_and_nothing_else() {
        assert!(form_post_is_guarded("/login"));
        assert!(form_post_is_guarded("/admin/users/alice/quota"));
        assert!(form_post_is_guarded("/admin/users/alice/anything-later"));
        assert!(!form_post_is_guarded("/admin/users"), "the list page itself is a GET");
        assert!(!form_post_is_guarded("/admin/userspace"), "a prefix is a path prefix");
        assert!(!form_post_is_guarded("/oauth/solid/token"));
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p brolly-server --lib -- same_origin_tests 2>&1 | tail -4`
Expected: compile error — `form_post_is_guarded` not found.

- [ ] **Step 3: Implement**

In `lib.rs`, add `"/admin/users/"` to `SAME_ORIGIN_FORMS` with a comment, and factor the match:

```rust
pub const SAME_ORIGIN_FORMS: &[&str] = &[
    "/login",
    "/register",
    "/logout",
    "/account/profile",
    "/account/security",
    "/account/apps",
    "/account/delete",
    // The three consent decisions (ADR 0011): one screen, three callers.
    "/oauth/solid/authorize",
    "/oauth/authorize",
    "/oauth/atproto/authorize",
    // An entry ending in `/` is a prefix: the console's per-member actions
    // carry the username in the path.
    "/admin/users/",
];

/// Is `path` one the same-origin rule guards? An entry ending in `/` is a
/// prefix, anything else an exact path.
fn form_post_is_guarded(path: &str) -> bool {
    SAME_ORIGIN_FORMS.iter().any(|entry| {
        if let Some(prefix) = entry.strip_suffix('/') {
            path.strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1)
        } else {
            *entry == path
        }
    })
}
```

and in `same_origin` replace `SAME_ORIGIN_FORMS.contains(&request.uri().path())` with `form_post_is_guarded(request.uri().path())`. Update the doc comment on `SAME_ORIGIN_FORMS` ("Every one of them is a page…") with one sentence: "An entry ending in `/` is a prefix."

- [ ] **Step 4: Run the unit test**

Run: `cargo test -p brolly-server --lib -- same_origin_tests 2>&1 | tail -4`
Expected: ok.

- [ ] **Step 5: Teach the invariant about templated actions**

In `server/tests/ui_invariants.rs`, inside `every_form_post_is_same_origin_checked`, replace

```rust
            if action.starts_with("{{") {
                continue;
            }
            assert!(
                list.contains(&action),
                "{}: form action {action} is not in SAME_ORIGIN_FORMS",
                path.display()
            );
```

with

```rust
            if action.starts_with("{{") {
                continue;
            }
            // A templated action — `/admin/users/{{ member.username }}/quota`
            // — is matched by its literal prefix against a prefix entry (one
            // ending in `/`); a literal action by an exact entry.
            let listed = match action.split_once("{{") {
                Some((literal, _)) => list
                    .iter()
                    .any(|entry| entry.ends_with('/') && literal.starts_with(entry)),
                None => list.contains(&action),
            };
            assert!(
                listed,
                "{}: form action {action} is not in SAME_ORIGIN_FORMS",
                path.display()
            );
```

Run: `cargo test -p brolly-server --test ui_invariants 2>&1 | tail -4` — ok (no templated action exists yet; Task 3.3 adds one, and this is what will hold it to the list).

### Task 3.3: The column, the form, the handler, the route (H4)

**Files:**
- Modify: `server/src/admin.rs` — `MemberView`, `UsersPage`, `users`; new `set_quota` handler and a shared `users_page` builder
- Modify: `server/templates/admin/users.html`
- Modify: `server/static/brolly.css` — `.visually-hidden`, `.inline-form`, `.chip-quota`
- Modify: `server/src/lib.rs` — the route in the `door` group
- Test: `server/tests/admin.rs`

- [ ] **Step 1: Write the failing tests**

In `server/tests/admin.rs`, add a helper after `get_as`:

```rust
/// `post`, as whoever holds `cookie`, from `origin` when given.
async fn post_as(
    router: &axum::Router,
    path: &str,
    body: &str,
    cookie: &str,
    origin: Option<&str>,
) -> (StatusCode, String, Option<String>) {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie);
    if let Some(origin) = origin {
        request = request.header(header::ORIGIN, origin);
    }
    let response = router
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    (status, body, location)
}

/// An admin's cookie and a member to act on.
async fn an_admin_and_alice(
    db: &brolly_test_support::TestDb,
    router: &axum::Router,
) -> (String, uuid::Uuid) {
    let invite = db::create_invite(&db.pool, None, 1, None, Some("admin"))
        .await
        .unwrap();
    let keeper = register(router, "keeper", &invite).await;
    let alice = db::create_user(&db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    (keeper, alice.id)
}
```

and, at the end of the file, the tests:

```rust
// --- quotas ------------------------------------------------------------------

#[tokio::test]
async fn an_admin_sets_a_members_quota_from_the_list() {
    let (db, _dir, router) = harness().await;
    let (keeper, alice) = an_admin_and_alice(&db, &router).await;

    let (status, _, location) =
        post_as(&router, "/admin/users/alice/quota", "quota=5G", &keeper, None).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location.as_deref(), Some("/admin/users"));
    assert_eq!(
        db::find_by_id(&db.pool, alice).await.unwrap().unwrap().quota_bytes,
        Some(5 << 30)
    );

    let (status, body) = get_as(&router, "/admin/users", Some(&keeper)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("5 GiB"), "{body}");
    assert!(body.contains("set by @keeper"), "{body}");
    assert!(
        body.contains(r#"value="5 GiB""#),
        "the field is prefilled with the formatted override: {body}"
    );
}

#[tokio::test]
async fn a_blank_quota_restores_the_default() {
    let (db, _dir, router) = harness().await;
    let (keeper, alice) = an_admin_and_alice(&db, &router).await;
    db::set_quota(&db.pool, alice, Some(5 << 30), None)
        .await
        .unwrap();

    let (status, _, _) =
        post_as(&router, "/admin/users/alice/quota", "quota=  ", &keeper, None).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        db::find_by_id(&db.pool, alice).await.unwrap().unwrap().quota_bytes,
        None
    );
    let (_, body) = get_as(&router, "/admin/users", Some(&keeper)).await;
    assert!(!body.contains("set by"), "the provenance is gone: {body}");
    assert!(
        body.contains(r#">default<"#),
        "the row says default (the placeholder says it too, so match the element): {body}"
    );
}

#[tokio::test]
async fn a_cli_set_quota_shows_a_date_and_no_name() {
    let (db, _dir, router) = harness().await;
    let (keeper, alice) = an_admin_and_alice(&db, &router).await;
    db::set_quota(&db.pool, alice, Some(2 << 30), None)
        .await
        .unwrap();

    let (_, body) = get_as(&router, "/admin/users", Some(&keeper)).await;
    assert!(body.contains("2 GiB"), "{body}");
    assert!(body.contains("set 20"), "a date, from this century: {body}");
    assert!(!body.contains("set by"), "{body}");
}

#[tokio::test]
async fn a_bad_size_is_named_against_the_row_and_sets_nothing() {
    let (db, _dir, router) = harness().await;
    let (keeper, alice) = an_admin_and_alice(&db, &router).await;

    let (status, body, _) =
        post_as(&router, "/admin/users/alice/quota", "quota=5X", &keeper, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("is not a unit"), "{body}");
    assert!(body.contains(r#"value="5X""#), "the bad value is kept: {body}");
    assert_eq!(
        db::find_by_id(&db.pool, alice).await.unwrap().unwrap().quota_bytes,
        None
    );
}

#[tokio::test]
async fn a_member_cannot_set_a_quota() {
    let (db, _dir, router) = harness().await;
    let (_keeper, alice) = an_admin_and_alice(&db, &router).await;
    let invite = db::create_invite(&db.pool, None, 1, None, None)
        .await
        .unwrap();
    let mallory = register(&router, "mallory", &invite).await;

    let (status, _, _) =
        post_as(&router, "/admin/users/alice/quota", "quota=5G", &mallory, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "the console does not exist for a member");
    assert_eq!(
        db::find_by_id(&db.pool, alice).await.unwrap().unwrap().quota_bytes,
        None
    );
}

#[tokio::test]
async fn a_cross_origin_quota_post_is_refused() {
    let (db, _dir, router) = harness().await;
    let (keeper, alice) = an_admin_and_alice(&db, &router).await;

    let (status, _, _) = post_as(
        &router,
        "/admin/users/alice/quota",
        "quota=5G",
        &keeper,
        Some("https://evil.example"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        db::find_by_id(&db.pool, alice).await.unwrap().unwrap().quota_bytes,
        None
    );
}

#[tokio::test]
async fn an_unknown_member_is_not_found() {
    let (db, _dir, router) = harness().await;
    let (keeper, _alice) = an_admin_and_alice(&db, &router).await;

    let (status, _, _) =
        post_as(&router, "/admin/users/nobody/quota", "quota=5G", &keeper, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
```

`uuid` is a dev-dependency of `brolly-server` (check `grep -n uuid server/Cargo.toml` — it is).

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p brolly-server --test admin -- quota 2>&1 | grep -E "^test|left|right"`
Expected: six FAIL with `left: 404` (no route yet) where 303, 400 or 200 is expected. `a_cross_origin_quota_post_is_refused` already PASSES: `same_origin` is a global layer and Task 3.2 listed the prefix, so the 403 comes before any route exists — that test is held by 3.2, and it stays here so the route cannot later escape the rule.

- [ ] **Step 3: The stylesheet**

Append to `server/static/brolly.css` (tokens only — no hex, no named colours; the invariant greps):

```css
/* A label that is read, not seen: the clip pattern. */
.visually-hidden {
  position: absolute;
  inline-size: 1px;
  block-size: 1px;
  overflow: hidden;
  clip-path: inset(50%);
  white-space: nowrap;
}

/* A form that sits inside a table cell. */
.inline-form { display: flex; gap: var(--sp--2); align-items: center; margin-block-start: var(--sp--2); }
.inline-form input { inline-size: 8em; }
/* Provenance, not status: muted, so it does not read as a role or a warning
   beside the chips that are. Every chip carries a background — a bare
   <mark> is the browser's own yellow, which the token invariant cannot see. */
.chip-quota { background: var(--muted); color: var(--muted-fg); }
```

The error beside a refused field reuses the existing `.error` rule (`brolly.css` ~line 312, `color: var(--destructive)`); no second class. `--muted`, `--muted-fg` and `--destructive` all exist in `tokens.css`.

- [ ] **Step 4: The handler and the page**

In `server/src/admin.rs`: add imports

```rust
use axum::Form;
use axum::extract::Path;
use brolly_domain::media::{format_size, parse_size};
use serde::Deserialize;
```

(check which are already imported; `serde` is a dependency of `brolly-server`). Replace `MemberView`, `UsersPage`, and `users` with:

```rust
/// One row, ready to render.
///
/// A view rather than the `UserRow` itself: `created_at` is an
/// `OffsetDateTime`, whose `Display` is a full RFC 3339 timestamp. A table of
/// those is unreadable, and date formatting is not the template's job.
struct MemberView {
    username: String,
    role: String,
    status: String,
    did: Option<String>,
    created: String,
    /// The effective quota, formatted.
    quota: String,
    /// `default`, `set by @keeper, 2026-10-26`, or `set 2026-10-26`.
    quota_note: String,
    quota_is_default: bool,
    /// What the pod holds, formatted — or `unknown` when the directory
    /// cannot be read. Not `0`: a console about to set a limit must not
    /// show a full pod as empty.
    usage: String,
    /// What the field shows: the formatted override, or the value an admin
    /// just submitted and had refused.
    quota_entered: String,
    quota_error: Option<String>,
}

#[derive(Template)]
#[template(path = "admin/users.html")]
struct UsersPage<'a> {
    chrome: Chrome<'a>,
    tabs: Vec<Tab>,
    members: Vec<MemberView>,
}

/// The members page, with at most one row's field carrying a refused value
/// and its error. `None` for a plain load.
async fn users_page<'a>(
    state: &'a AppState,
    refused: Option<(&str, &str, &str)>,
) -> Result<UsersPage<'a>, ()> {
    let rows = db::list_users(&state.pool).await.map_err(|e| {
        tracing::error!(error = %e, "admin member list failed");
    })?;
    let members = rows
        .into_iter()
        .map(|row| {
            // `UserRow` is not a `User`, so the override-or-default rule is
            // restated here — the same rule as `User::quota`, the one other
            // place it lives.
            let quota_bytes = row
                .quota_bytes
                .map(|b| u64::try_from(b).unwrap_or(0))
                .unwrap_or(state.pod_quota_bytes);
            let quota_note = match (row.quota_bytes, row.quota_set_at, row.quota_set_by) {
                (None, _, _) => "default".to_string(),
                (Some(_), Some(at), Some(by)) => format!("set by @{by}, {}", at.date()),
                (Some(_), Some(at), None) => format!("set {}", at.date()),
                // The CHECK says this cannot happen; say so rather than lie.
                (Some(_), None, _) => "set".to_string(),
            };
            let (quota_entered, quota_error) = match refused {
                Some((name, entered, error)) if name == row.username => {
                    (entered.to_string(), Some(error.to_string()))
                }
                _ => (
                    row.quota_bytes
                        .map(|b| format_size(u64::try_from(b).unwrap_or(0)))
                        .unwrap_or_default(),
                    None,
                ),
            };
            MemberView {
                usage: state
                    .stores
                    .pod_bytes(row.id)
                    .map(format_size)
                    .unwrap_or_else(|_| "unknown".to_string()),
                username: row.username,
                role: row.role,
                status: row.status,
                did: row.did_plc,
                // Date only. The time an account was created to the second has
                // never answered a question an operator was actually asking.
                created: row.created_at.date().to_string(),
                quota: format_size(quota_bytes),
                quota_is_default: row.quota_bytes.is_none(),
                quota_note,
                quota_entered,
                quota_error,
            }
        })
        .collect();
    Ok(UsersPage {
        chrome: state.chrome(),
        tabs: tabs("/admin/users"),
        members,
    })
}

/// `GET /admin/users`
pub async fn users(State(state): State<AppState>, jar: CookieJar) -> Response {
    if let Err(response) = require_admin(&state, &jar, "/admin/users").await {
        return response;
    }
    match users_page(&state, None).await {
        Ok(page) => render(&page),
        Err(()) => server_error(),
    }
}

#[derive(Deserialize)]
pub struct QuotaForm {
    quota: String,
}

/// `POST /admin/users/{username}/quota` — the console's first write.
///
/// Empty clears the override; otherwise the one size grammar. A refused size
/// re-renders the list as a 400 with the message against that row and the
/// value kept, and sets nothing. Lowering a quota below what a member holds
/// refuses their next add until they are under it; it deletes nothing.
pub async fn set_quota(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(username): Path<String>,
    Form(form): Form<QuotaForm>,
) -> Response {
    let admin = match require_admin(&state, &jar, "/admin/users").await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let member = match db::find_by_username(&state.pool, &username).await {
        Ok(Some(member)) => member,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!(error = %e, "member lookup failed");
            return server_error();
        }
    };

    let entered = form.quota.trim();
    let quota_bytes = if entered.is_empty() {
        None
    } else {
        match parse_size(entered) {
            Ok(bytes) => Some(i64::try_from(bytes).unwrap_or(i64::MAX)),
            Err(e) => {
                let error = e.to_string();
                return match users_page(&state, Some((username.as_str(), entered, error.as_str()))).await {
                    Ok(page) => (StatusCode::BAD_REQUEST, render(&page)).into_response(),
                    Err(()) => server_error(),
                };
            }
        }
    };

    if let Err(e) = db::set_quota(&state.pool, member.id, quota_bytes, Some(admin.id)).await {
        tracing::error!(error = %e, member = %member.id, "setting a quota failed");
        return server_error();
    }
    Redirect::to("/admin/users").into_response()
}
```

`render` returns a `Response` (check its signature in `lib.rs`: `pub fn render<T: Template>(t: &T) -> Response`); `(StatusCode, Response).into_response()` keeps the body and overrides the status.

`users_page` names its lifetime: the page borrows `state` for `Chrome`, and with three other reference parameters elision cannot pick one, so `'_` in the return type would be E0106. Both callers hold `state` across the render.

The date in the note is ISO (`2026-10-26`, from `date()`), as the Joined column already is — the spec's `26 Oct 2026` was illustrative; the spec says so now.

- [ ] **Step 5: The template**

In `server/templates/admin/users.html`, add a header cell after "Federation identity":

```html
            <th scope="col">Quota</th>
```

and a cell after the federation-identity `<td>`:

```html
            <td>
              <span class="mono">{{ member.quota }}</span>
              {% if member.quota_is_default %}
              <span class="hint">default</span>
              {% else %}
              <mark class="chip chip-quota">{{ member.quota_note }}</mark>
              {% endif %}
              <span class="hint">{{ member.usage }} used</span>
              <form method="post" action="/admin/users/{{ member.username }}/quota" class="inline-form">
                <label class="visually-hidden" for="quota-{{ member.username }}">Quota for @{{ member.username }}</label>
                <input id="quota-{{ member.username }}" name="quota" value="{{ member.quota_entered }}" placeholder="5G, blank for default">
                <button type="submit">Save</button>
                {% if let Some(error) = member.quota_error %}
                <span class="error">{{ error }}</span>
                {% endif %}
              </form>
            </td>
```

The `<form …>` must stay on one line: the invariant reads forms line by line.

- [ ] **Step 6: The route**

In `server/src/lib.rs`, in the `door` router after `.route("/admin/users", get(admin::users))`:

```rust
        .route("/admin/users/{username}/quota", post(admin::set_quota))
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test -p brolly-server --test admin --test ui_invariants > /tmp/q.log 2>&1; grep -E "test result|FAILED|panicked" -A3 /tmp/q.log`
Expected: both ok, including the seven quota tests and `every_form_post_is_same_origin_checked` (which now sees the templated action and finds `/admin/users/`). If the invariant's hex grep flags the CSS, you used a literal colour — use a token.

- [ ] **Step 8: Look at it**

Run the app (`docs/running-locally.md`), log in as an admin, open `/admin/users`. Check: the column renders at 1280px and the table still fits (or scrolls) at 375px; tab to the field and Save works by keyboard; a bad value shows its message beside that row and nowhere else. Fix anything that doesn't hold before committing. If the app cannot be run here, say so in the commit body.

- [ ] **Step 9: Lints and commit**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings > /tmp/c.log 2>&1; grep -E "^(warning|error)" -A4 /tmp/c.log`
Expected: clean.

```bash
git add identity/src/db.rs identity/tests/persistence.rs server/src/admin.rs server/src/lib.rs server/templates/admin/users.html server/static/brolly.css server/tests/admin.rs server/tests/ui_invariants.rs
git commit -F - <<'EOF'
feat(admin): a member's quota, set from the console (quotas 3)

The console's first write. Each row of /admin/users shows the member's
effective quota, whether it is the default or who set it and when, what
the pod holds, and a field: a size to set an override, blank to clear
it. The handler is the shape slice 2's actions will take — require_admin,
a form per row, the same-origin and apex-only guards, a redirect back to
the list — and a refused size re-renders the list with the message
against that row and the value kept, setting nothing.

The list stays one query: the quota and its provenance ride on UserRow,
the setter's name by a self-join. Usage is a directory walk per row —
not a store open, which is the thing ADR 0005 forbids, and the row's
doc comment now draws that line.

The action carries the username in its path, so SAME_ORIGIN_FORMS gains
its first prefix entry, and the invariant that reads every form out of
the templates learns to match a templated action by its literal prefix.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
EOF
```

(`server/src/lib.rs`, `server/tests/admin.rs` and `server/tests/ui_invariants.rs` carry the operator's theme hunks: stage each theme-free with `git apply --cached` as the preamble describes. `lib.rs`'s theme hunks are the `theme_css` field, the `Chrome` field and its assignment — drop all three from the patch.)

---

## Chunk 4: The overview

### Task 4.1: Usage against quota, with a meter (H6)

**Files:**
- Modify: `server/src/account.rs` — `Overview` struct and `overview` handler (~lines 103-140)
- Modify: `server/templates/account/overview.html:34-35`
- Modify: `server/static/brolly.css`
- Test: `server/tests/dashboard.rs`

- [ ] **Step 1: Write the failing tests**

In `server/tests/dashboard.rs`, after `the_overview_shows_the_member_what_is_theirs`:

```rust
/// A member sees what they hold against what they may hold — the same
/// number the writes enforce — so the quota is news before a 507 makes it
/// news.
#[tokio::test]
async fn the_overview_shows_usage_against_the_quota() {
    let h = harness().await;
    let cookie = h.login().await;

    let reply = h.get("/account", Some(&cookie)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains("of 1 GiB"), "the instance default: {}", reply.body);
    assert!(
        reply.body.contains(r#"<meter min="0" max="1073741824""#),
        "{}",
        reply.body
    );

    db::set_quota(&h.db.pool, h.user, Some(5 << 30), None)
        .await
        .unwrap();
    let reply = h.get("/account", Some(&cookie)).await;
    assert!(reply.body.contains("of 5 GiB"), "the override: {}", reply.body);
    assert!(
        reply.body.contains(r#"max="5368709120""#),
        "the meter's ceiling is the effective quota: {}",
        reply.body
    );
    assert!(
        reply.body.contains(r#"high="4831838208""#),
        "it turns at 90%: {}",
        reply.body
    );
}
```

(`h.user` and `h.db` exist on the dashboard `Harness` — see its definition at the top of the file.)

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p brolly-server --test dashboard -- usage_against 2>&1 | grep -E "^test|default:|panicked" | head -4`
Expected: FAIL — the body says `… bytes`, no "of".

- [ ] **Step 3: Implement**

In `server/src/account.rs`, after the `Overview` struct's `pod_bytes` field add four:

```rust
    pod_bytes: u64,
    /// The effective quota: an admin's override or the instance default
    /// (`User::quota`). The meter's ceiling.
    quota_bytes: u64,
    /// 90% of it: where the meter turns.
    warn_at: u64,
    /// Both, formatted for the words beside the meter.
    used: String,
    quota: String,
```

and in `overview`:

```rust
    let pod_bytes = state.stores.pod_bytes(session.user.id).unwrap_or(0);
    let quota_bytes = session.user.quota(state.pod_quota_bytes);
    render(&Overview {
        chrome: state.chrome(),
        tabs: tabs("/account"),
        username: &session.user.username,
        webid: webid::webid(&session.user.username, &state.base_domain),
        storage_root: routing::storage_root(&session.user.username, &state.base_domain),
        did: session.user.did_plc.as_deref(),
        pod_bytes,
        quota_bytes,
        warn_at: quota_bytes / 10 * 9,
        used: brolly_domain::media::format_size(pod_bytes),
        quota: brolly_domain::media::format_size(quota_bytes),
        is_admin: session.user.is_admin(),
    })
```

In `server/templates/account/overview.html`, replace

```html
        <dt>Data stored</dt>
        <dd>{{ pod_bytes }} bytes</dd>
```

with

```html
        <dt>Data stored</dt>
        <dd>
          <meter min="0" max="{{ quota_bytes }}" value="{{ pod_bytes }}" high="{{ warn_at }}" class="usage" aria-label="Data stored, against the quota"></meter>
          <span>{{ used }} of {{ quota }}</span>
        </dd>
```

The meter is empty and the words live once, in the span: a browser renders
meter content only when it cannot render a meter (none this product
supports), while a text browser renders both — and would read the figures
twice. The `aria-label` gives the meter the name `<dt>` only gives it
visually.

Append to `server/static/brolly.css`:

```css
/* Usage against quota on the overview: the native meter, full width, and
   the words beside it carry the same figures for a screen reader. */
meter.usage { display: block; inline-size: 100%; block-size: var(--sp-0); margin-block-end: var(--sp--2); }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p brolly-server --test dashboard --test ui_invariants > /tmp/q.log 2>&1; grep -E "test result|FAILED" /tmp/q.log`
Expected: both ok. (`high` with `value > max` — an admin set below usage — renders the meter full; browsers clamp, and the text says `1.2 GiB of 1 GiB`, which is the truth.)

- [ ] **Step 5: Look at it**

Run the app, log in, open `/account`. Check the meter at 375px and 1280px, in light and dark schemes (the token layer carries both); the words read correctly with the meter hidden (text browser or screen reader). If the app cannot be run here, say so in the commit body.

- [ ] **Step 6: Lints and commit**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings > /tmp/c.log 2>&1; grep -E "^(warning|error)" -A4 /tmp/c.log; ./tools/check-doc-paths.sh`
Expected: clean; `doc paths ok`.

```bash
git add server/src/account.rs server/templates/account/overview.html server/static/brolly.css server/tests/dashboard.rs
git commit -F - <<'EOF'
feat(account): usage against quota on the overview (quotas 4)

"432537600 bytes" told a member what they held and nothing about the
ceiling, so their first notice of a quota was a 507. The overview now
reads "412.5 MiB of 1 GiB" with a native meter that turns at ninety
percent — the same number the writes enforce, an admin's override or
the instance default, from the one place the two combine. The words
beside the meter carry the same figures, so a screen reader and a text
browser read what a sighted member sees; a member an admin has set
below their usage sees the meter full and the text honest.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
EOF
```

### Task 4.2: Close out

- [ ] **Step 1: The whole workspace**

Run: `cargo test --workspace > /tmp/all.log 2>&1; grep -E "FAILED|panicked" /tmp/all.log; grep -c "test result: ok" /tmp/all.log`
Expected: the first grep prints nothing — that is the criterion. The count is a sanity check only (one `ok` line per test binary and doc-test run; it was 20 the last time the workspace ran). Budget 15 minutes; the pod suites are slow.

- [ ] **Step 2: Spec status**

In `docs/specs/2026-10-26-member-quotas.md`, change the `**Status:**` line to `**Status:** Implemented, 2026-MM-DD, in four commits: <hashes>.` (keep the rest of the paragraph) and commit:

```bash
git add docs/specs/2026-10-26-member-quotas.md
git commit -m "docs(admin): member quotas are implemented

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

- [ ] **Step 3: Report**

Tell the operator: the four commits, what was not run (the CLI against a real stack, the visual checks) if anything, and that the commits are local — there is no remote.
