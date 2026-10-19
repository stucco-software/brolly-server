-- App passwords (stage 2, A/B).
--
-- The HTTP API spec's own credential for clients that cannot do OAuth: a
-- server-chosen secret the member creates once, sees once, and revokes by
-- row. `privileged` is the one flag the spec gives it — access to "possibly
-- sensitive account state" (the email fields on the session endpoints).
CREATE TABLE atproto_app_passwords (
    id            UUID PRIMARY KEY,
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    -- SHA-256, not Argon2: this is a server-chosen high-entropy secret (the
    -- `hash_secret` rule), and `createSession` reads it as an indexed
    -- equality check before any Argon2 run.
    password_hash TEXT NOT NULL,
    privileged    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, name)
);

-- The UNIQUE index is the lookup, not decoration: `createSession`'s first
-- password check is an indexed SHA-256 equality against this column (2, A).
-- 16 characters of [a-z0-9] are ~82 bits, so a collision is a formality.
CREATE UNIQUE INDEX atproto_app_passwords_hash_idx
    ON atproto_app_passwords (password_hash);
