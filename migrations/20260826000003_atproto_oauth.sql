-- ATProtocol OAuth.
--
-- A third set of tables rather than a shared one, for the reason ADR 0008 gave
-- for keeping the surfaces separate: the three protocols disagree about what an
-- OAuth request even contains. ATProtocol mandates PAR and DPoP and identifies
-- clients by a metadata URL; Mastodon has client secrets and no PAR; Solid has
-- neither secrets nor PAR. One table would be mostly null in every direction.

-- Pushed authorization requests (RFC 9126).
--
-- ATProtocol requires PAR: the client posts the whole authorization request
-- here first and gets back an opaque handle. The parameters never travel
-- through the browser, so they cannot be tampered with in the address bar.
CREATE TABLE atproto_par_requests (
    request_uri    TEXT PRIMARY KEY,
    client_id      TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    scope          TEXT NOT NULL,
    state          TEXT,
    -- PKCE is mandatory here, unlike Mastodon's optional form.
    code_challenge TEXT NOT NULL,
    -- The DPoP key the eventual token is bound to, pledged up front.
    dpop_jkt       TEXT NOT NULL,
    login_hint     TEXT,
    expires_at     TIMESTAMPTZ NOT NULL,
    used_at        TIMESTAMPTZ
);

CREATE TABLE atproto_auth_codes (
    code_hash      TEXT PRIMARY KEY,
    client_id      TEXT NOT NULL,
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri   TEXT NOT NULL,
    scope          TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    dpop_jkt       TEXT NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    used_at        TIMESTAMPTZ
);

-- Access and refresh tokens, both DPoP-bound.
--
-- Unlike Mastodon's, these expire: ATProtocol clients refresh, and a
-- non-expiring bearer token is not something the protocol's threat model
-- contemplates.
CREATE TABLE atproto_tokens (
    token_hash  TEXT PRIMARY KEY,
    kind        TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
    client_id   TEXT NOT NULL,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope       TEXT NOT NULL,
    dpop_jkt    TEXT NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX atproto_tokens_user_idx ON atproto_tokens (user_id);
