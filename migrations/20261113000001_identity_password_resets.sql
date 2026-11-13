-- Password reset links (spec piece 4). brolly mints them through the service
-- API and redeems them on /reset; the front end emails them. Only the token's
-- hash is stored, like sessions. One hour, single use, and redeeming any link
-- uses up the member's others. Deleting the member deletes their links.
CREATE TABLE password_resets (
    token_hash  TEXT PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ
);

CREATE INDEX password_resets_user_idx ON password_resets (user_id, created_at);
