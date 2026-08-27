-- The commit event log the firehose serves.
--
-- A relay or AppView that drops its connection resumes from a cursor rather
-- than resyncing every repo on the instance, so the events have to outlive the
-- connection that would have carried them.
--
-- Pointers, not content: an event names the repo, the commit CID and the paths
-- touched. A consumer that wants the records fetches them, which keeps this
-- from becoming a second copy of every write (D5).
CREATE TABLE atproto_firehose (
    -- The cursor. Monotonic across the whole instance, because a consumer
    -- subscribes to the instance rather than to one repo.
    seq        BIGSERIAL PRIMARY KEY,
    did        TEXT NOT NULL,
    -- The commit this event announces, and the one before it.
    commit_cid TEXT NOT NULL,
    prev_cid   TEXT,
    -- Per-repo revision, so a consumer can tell ordering within one repo
    -- without reasoning about the global sequence.
    rev        BIGINT NOT NULL,
    -- `create`, `update` or `delete`, and the record path it applied to.
    action     TEXT NOT NULL CHECK (action IN ('create', 'update', 'delete')),
    path       TEXT NOT NULL,
    -- Null for a delete.
    record_cid TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX atproto_firehose_did_idx ON atproto_firehose (did, seq);
