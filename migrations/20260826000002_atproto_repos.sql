-- Where a member's ATProtocol repo currently points.
--
-- The blocks themselves are content-addressed on disk (D2, ADR 0013's
-- shape) — this is only the pointer to the newest commit, which is the one
-- piece atrium does not decide the home of.
--
-- Operational, not content: losing this table costs a rebuild from the block
-- set, not data. That is the same test every other Postgres table here has to
-- pass, and it is why the record bodies are not in it.
CREATE TABLE atproto_repos (
    user_id    UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,

    -- The root CID as its string form. Stored as text because that is how it
    -- travels in every wire format that mentions it, and re-encoding on each
    -- read would buy nothing.
    root_cid   TEXT NOT NULL,

    -- Monotonic per-repo revision, as ATProtocol's sync protocol expects. A
    -- consumer uses it to tell whether it is behind without fetching blocks.
    rev        BIGINT NOT NULL DEFAULT 0,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
