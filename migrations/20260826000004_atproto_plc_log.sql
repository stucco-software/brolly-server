-- The PLC operation log.
--
-- Identity operations, not pod content. Storing them here does not make
-- Postgres a second source of truth for anything a member wrote — these are
-- the instance's record of identity actions it took, in the same category as
-- the signing keys already in `user_keys`.
--
-- It exists because PLC operations form a **chain**: each names its
-- predecessor by CID, so rotating a key requires knowing the current head.
-- Without a log, the only way to find it would be to ask the directory, which
-- makes recovery depend on the network being reachable at exactly the moment
-- something has gone wrong.
CREATE TABLE atproto_plc_operations (
    cid          TEXT PRIMARY KEY,
    user_id      UUID REFERENCES users(id) ON DELETE CASCADE,
    did          TEXT NOT NULL,
    -- The signed operation, verbatim. Re-deriving it would re-derive the CID,
    -- and any drift there would silently break the chain.
    operation    JSONB NOT NULL,
    -- Null for genesis.
    prev         TEXT,
    -- Null until the directory has accepted it. A DID that exists locally and
    -- not in the directory is a real state, and it has to be visible so it can
    -- be retried rather than assumed.
    submitted_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX atproto_plc_operations_user_idx ON atproto_plc_operations (user_id, created_at);
