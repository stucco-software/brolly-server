-- The revision becomes a TID: 13 base32 characters, timestamp-sortable — the
-- form every ATProtocol consumer compares, orders and echoes. A BIGINT counter
-- is not a slightly wrong TID; it is a parse failure on the consumer's side.
--
-- Stored as text because that is how a rev travels in every wire format that
-- mentions one, so the hot path re-encodes nothing (1, A). The encoding is
-- order-preserving, so text comparison is TID comparison and the head update's
-- `rev < $new` guard stays correct — which is why both columns are COLLATE "C":
-- a database locale's collation is not guaranteed to order base32 text
-- numerically, and pinning it makes lexicographic == numeric structural rather
-- than incidental.
--
-- Existing rows are converted here, in the migration, not at first boot: a
-- rollback of the binary must not find a half-TID table. The revs are derived
-- from each row's own timestamp — created_at for the events, updated_at for the
-- heads — minted per repo in seq order and incremented past a collision where
-- two rows share a millisecond, so every repo's derived revs come out strictly
-- increasing. These are derived values, not the old signed commits' own revs
-- (which nothing ever read back); from the next write on, the stored rev is the
-- commit's own (1, A).
--
-- The layout matches atrium-api's `Tid::from_datetime`: 54 bits of epoch
-- microseconds shifted up, 10 bits of clock id below. The conversion keeps the
-- clock id at zero and breaks same-millisecond ties with +1, which is the clock
-- id incrementing — the same rule the Rust mint applies.

-- Session-local helpers: they vanish with the migration's connection and are
-- not schema, so the table shapes stay the migration's only footprint.
CREATE FUNCTION pg_temp.tid_bits(at TIMESTAMPTZ) RETURNS BIGINT
    LANGUAGE sql IMMUTABLE
AS $fn$
    SELECT (extract(epoch FROM at) * 1000000)::BIGINT << 10
$fn$;

CREATE FUNCTION pg_temp.tid_text(bits BIGINT) RETURNS TEXT
    LANGUAGE plpgsql IMMUTABLE
AS $fn$
DECLARE
    alphabet TEXT := '234567abcdefghijklmnopqrstuvwxyz';
    out TEXT := '';
    v BIGINT := bits;
BEGIN
    -- 13 characters of 5 bits, most significant first — the encoding
    -- atrium-api's s32_encode produces.
    FOR i IN 1..13 LOOP
        out := substr(alphabet, (v & 31)::INT + 1, 1) || out;
        v := v >> 5;
    END LOOP;
    RETURN out;
END
$fn$;

-- Events first: the head conversion below compares against their result.
ALTER TABLE atproto_firehose
    ALTER COLUMN rev TYPE TEXT COLLATE "C" USING '2222222222222';

DO $conv$
DECLARE
    evt RECORD;
    last_did TEXT := NULL;
    last_bits BIGINT := 0;
    cand BIGINT;
BEGIN
    -- Per repo, in seq order: derive a TID from the row's timestamp, and
    -- where the derivation does not clear the previous row — two rows share a
    -- millisecond, or a clock stepped backwards — increment past the
    -- collision, so each repo's derived revs are strictly increasing (1, A).
    FOR evt IN
        SELECT seq, did, pg_temp.tid_bits(created_at) AS bits
        FROM atproto_firehose
        ORDER BY did, seq
    LOOP
        cand := evt.bits;
        IF evt.did = last_did THEN
            cand := GREATEST(cand, last_bits + 1);
        END IF;
        UPDATE atproto_firehose SET rev = pg_temp.tid_text(cand) WHERE seq = evt.seq;
        last_did := evt.did;
        last_bits := cand;
    END LOOP;
END
$conv$;

ALTER TABLE atproto_repos
    ALTER COLUMN rev TYPE TEXT COLLATE "C" USING '2222222222222';

-- The head must not sit below its repo's own last event: the next write mints
-- past the head, and the `rev <` guard would let it land at or below an event
-- the log already holds, breaking per-repo ordering there. Derived from the
-- row's updated_at, raised to the repo's highest converted event rev (matched
-- through the member's DID) when that is higher.
UPDATE atproto_repos r
SET rev = GREATEST(
    pg_temp.tid_text(pg_temp.tid_bits(r.updated_at)) COLLATE "C",
    COALESCE((
        SELECT max(f.rev)
        FROM atproto_firehose f
        JOIN users u ON u.did_plc = f.did
        WHERE u.id = r.user_id
    ), '')
);
