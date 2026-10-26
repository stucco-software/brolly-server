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
