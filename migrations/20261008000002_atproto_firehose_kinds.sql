-- The log grows the other two event kinds the stream defines (1, E).
--
-- One table still, and one sequence: a consumer subscribes to the instance,
-- not to a kind, and its cursor has to order a commit against an identity
-- change against a takedown. `kind` says what the rest of the row means; the
-- commit-specific columns go nullable rather than to their own tables,
-- because a nullable column is the shape a shared sequence already implies —
-- and `#sync` stays a frame type with no row at all (1, E).
--
-- Existing rows are commits — every row this log has ever held was one — so
-- `kind` is backfilled here, in the migration, not at first boot: a rollback
-- of the binary must not find a half-kindless table. (The ops table needs
-- nothing: an op row exists only where a commit does, and a commit is still
-- one event, n ops.)
ALTER TABLE atproto_firehose
    ADD COLUMN kind TEXT,
    -- `#identity`: the handle the DID now claims, if it claims one on the wire.
    ADD COLUMN handle TEXT,
    -- `#account`: whether the repo is available, and why not if it is not.
    -- The Sync spec's known values — a free-text status is a vocabulary a
    -- consumer cannot dispatch on (1, E).
    ADD COLUMN active BOOLEAN,
    ADD COLUMN status TEXT
        CHECK (status IN ('takendown', 'suspended', 'deleted', 'deactivated'));

UPDATE atproto_firehose SET kind = 'commit';

ALTER TABLE atproto_firehose
    ALTER COLUMN kind SET NOT NULL,
    ADD CONSTRAINT atproto_firehose_kind_values_check
        CHECK (kind IN ('commit', 'identity', 'account')),
    ALTER COLUMN commit_cid DROP NOT NULL,
    ALTER COLUMN rev DROP NOT NULL;

-- The commit columns belong to commits and to nothing else: "an #identity
-- event carries none of them" (1, E), and a nullable column nothing writes
-- is a lie the next reader has to reason about. A commit row that cannot say
-- which commit it announces is not an event a consumer can frame; an identity
-- or account row that carried them would be two events wearing one.
ALTER TABLE atproto_firehose
    ADD CONSTRAINT atproto_firehose_commit_is_a_commit_check
        CHECK ((kind = 'commit') = (commit_cid IS NOT NULL AND rev IS NOT NULL)),
    ADD CONSTRAINT atproto_firehose_only_commits_carry_commit_pointers_check
        CHECK (kind = 'commit'
               OR (prev_cid IS NULL AND since_rev IS NULL AND prev_data IS NULL));

-- An #account event always answers whether the account is active — that is
-- the whole message — and `status` is an account fact, not a general one.
ALTER TABLE atproto_firehose
    ADD CONSTRAINT atproto_firehose_account_says_active_check
        CHECK (kind <> 'account' OR active IS NOT NULL),
    ADD CONSTRAINT atproto_firehose_status_is_an_account_fact_check
        CHECK (kind = 'account' OR status IS NULL);
