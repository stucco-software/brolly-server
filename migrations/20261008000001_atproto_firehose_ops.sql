-- One event, n ops (1, B).
--
-- The log's row held one op — action, path, record_cid on atproto_firehose —
-- because every write was one op. applyWrites is one commit with one op per
-- write, so the ops move to their own table, one row per op in the order the
-- batch applied them, and the event row stays the commit: its CIDs, its rev,
-- the rev and MST root it follows (since_rev / prev_data, added ahead of this
-- in 20261007000002 and written from here on).
--
-- The op rows carry pointers only — actions, paths, CIDs, and the per-op prev
-- the write path captures while the old MST is open, which chunk 3's frames
-- emit and nothing can reconstruct afterwards (1, D). No record content: the
-- log is not a second copy of the repo (D5).
--
-- Existing rows are single-op events from the old shape; each becomes one op
-- row at position 0, and the columns they leave behind are dropped — nullable
-- dead columns are a shape the next migration would have to reason about.

CREATE TABLE atproto_firehose_ops (
    -- The commit event this op belongs to. Cascades, so log pruning cannot
    -- strand an op.
    seq        BIGINT NOT NULL REFERENCES atproto_firehose (seq) ON DELETE CASCADE,
    -- The op's place in the batch, in apply order.
    position   INT NOT NULL,
    action     TEXT NOT NULL CHECK (action IN ('create', 'update', 'delete')),
    path       TEXT NOT NULL,
    -- Null for a delete.
    record_cid TEXT,
    -- The record CID an update replaced or a delete removed; undefined for a
    -- create (1, D).
    prev_cid   TEXT,
    PRIMARY KEY (seq, position)
);

INSERT INTO atproto_firehose_ops (seq, position, action, path, record_cid)
SELECT seq, 0, action, path, record_cid FROM atproto_firehose;

ALTER TABLE atproto_firehose
    DROP COLUMN action,
    DROP COLUMN path,
    DROP COLUMN record_cid;
