-- Legacy session tokens (stage 2, A).
--
-- The HTTP API spec says clients "should treat the tokens as opaque string
-- tokens" and that JWT shape "is not a stable part of the specification", so
-- brolly stores what it controls: 32 random bytes, hex, SHA-256-hashed like
-- every other credential in the tree. Its own table because `atproto_tokens`
-- is `dpop_jkt NOT NULL` and `client_id NOT NULL` — two columns a legacy
-- session can never fill — and ADR 0008's rule for surfaces that disagree is
-- separate tables, not mostly-null columns.
CREATE TABLE atproto_legacy_tokens (
    token_hash  TEXT PRIMARY KEY,
    -- The kind is part of the lookup, not a check after it: a refresh token
    -- presented as an access token fails the query, which is the domain
    -- separation the spec's `typ` headers approximate.
    kind        TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- The provenance the privilege matrix reads (2, B): NULL is the primary
    -- password, a row is the app password this session was created through.
    -- CASCADE is the whole point of opaque rows: revoking the app password
    -- kills its sessions immediately, not at their next refresh.
    app_password_id UUID REFERENCES atproto_app_passwords(id) ON DELETE CASCADE,
    -- The pair and every rotation of it share one id: what `refreshSession`
    -- rotates under, and what `deleteSession` ends wholesale.
    session_id  UUID NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX atproto_legacy_tokens_session_idx ON atproto_legacy_tokens (session_id);
CREATE INDEX atproto_legacy_tokens_user_idx ON atproto_legacy_tokens (user_id);
