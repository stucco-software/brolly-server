-- A refresh token belongs to a family: the grant it descends from through
-- rotation. Every rotation issues a token in the same family, so a spent
-- token presented again — theft made visible, since one of the two holders
-- is not the client — can end the whole grant rather than just refuse the
-- replay. And a family has one absolute lifetime, copied forward through
-- every rotation: without it, rotation alone makes a grant immortal, since
-- each replacement started a fresh sliding window.
--
-- No database default for `family`: the application always supplies it, and
-- gen_random_uuid() is not available on every Postgres the tests run against.
ALTER TABLE solid_refresh_tokens
    ADD COLUMN family UUID,
    ADD COLUMN grant_expires_at TIMESTAMPTZ;

-- Tokens issued before this migration: each is its own family — a UUID
-- derived from its hash, so the backfill is deterministic — and its sliding
-- expiry is the best absolute one there is.
UPDATE solid_refresh_tokens
   SET family = md5(token_hash)::uuid,
       grant_expires_at = expires_at
 WHERE family IS NULL;

ALTER TABLE solid_refresh_tokens
    ALTER COLUMN family SET NOT NULL,
    ALTER COLUMN grant_expires_at SET NOT NULL;

CREATE INDEX solid_refresh_tokens_family_idx ON solid_refresh_tokens (family);
