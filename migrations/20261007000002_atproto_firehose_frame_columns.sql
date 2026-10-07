-- The two firehose columns the lexicon's frames carry, added ahead of the
-- chunks that write them (1, D):
--
--   since_rev  the rev this commit is based on — the previous commit's own
--              rev, null on a repo's first commit. (Today's frames wrongly
--              use the previous commit's *CID*; chunk 3 corrects the frame.)
--   prev_data  the previous MST root — "effectively required for MST
--              inversion", so no inductive consumer can work without it.
--
-- Nullable and unwritten until those chunks land; an event with no predecessor
-- carries neither. `since_rev` is a TID, so it takes the same deterministic
-- collation as the rev columns; `prev_data` is an opaque CID nothing orders.
ALTER TABLE atproto_firehose
    ADD COLUMN since_rev TEXT COLLATE "C",
    ADD COLUMN prev_data TEXT;
