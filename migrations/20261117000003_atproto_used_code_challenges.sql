-- Used PKCE code_challenges (stage 2, H).
--
-- The profile's PKCE section: servers "must prevent reuse of code_challenge
-- values across sessions (at least within some reasonable time frame, such as
-- a 24 hour period)" — defense in depth against a challenge-carrying
-- interceptor. The challenge value is itself a SHA-256, so it is its own
-- primary key.
--
-- A row only has to outlive the 24-hour window. `use_code_challenge`
-- (adapters/atproto/src/oauth.rs) prunes expired rows in the same statement
-- that inserts, by the application's clock — the dpop_jti pattern (S7): the
-- database's clock would let a running-ahead prune forget a row the
-- application still counts. There is no background job.
CREATE TABLE atproto_used_code_challenges (
    code_challenge TEXT PRIMARY KEY,
    expires_at     TIMESTAMPTZ NOT NULL
);

CREATE INDEX atproto_used_code_challenges_expires
    ON atproto_used_code_challenges (expires_at);
