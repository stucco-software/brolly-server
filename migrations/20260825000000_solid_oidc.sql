-- Solid-OIDC provider state.
--
-- Secrets are stored hashed throughout, for the same reason as sessions: a
-- database read must not yield a usable credential.

-- Dynamically registered clients (RFC 7591). Browser apps register on first
-- login and get a urn:uuid: identifier; there is no client secret, because a
-- browser app cannot keep one.
CREATE TABLE solid_clients (
    client_id     TEXT PRIMARY KEY,
    client_name   TEXT,
    redirect_uris TEXT[] NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Authorization codes. Single-use and short-lived.
CREATE TABLE solid_auth_codes (
    code_hash      TEXT PRIMARY KEY,
    client_id      TEXT NOT NULL REFERENCES solid_clients(client_id) ON DELETE CASCADE,
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    webid          TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    -- PKCE (RFC 7636). S256 only; the challenge is stored, never the verifier.
    code_challenge TEXT NOT NULL,
    scope          TEXT NOT NULL,
    nonce          TEXT,
    -- The DPoP key the eventual access token will be bound to.
    dpop_jkt       TEXT,
    expires_at     TIMESTAMPTZ NOT NULL,
    -- Set on redemption. Kept rather than deleted so a replay is detectable
    -- instead of merely failing.
    used_at        TIMESTAMPTZ
);

-- Refresh tokens, rotated on every use.
CREATE TABLE solid_refresh_tokens (
    token_hash  TEXT PRIMARY KEY,
    client_id   TEXT NOT NULL REFERENCES solid_clients(client_id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    webid       TEXT NOT NULL,
    scope       TEXT NOT NULL,
    dpop_jkt    TEXT,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ
);

CREATE INDEX solid_refresh_tokens_user_idx ON solid_refresh_tokens (user_id);

-- The provider's ES256 signing key. One row per key so a rotation can publish
-- both while old tokens drain.
CREATE TABLE solid_provider_keys (
    kid         TEXT PRIMARY KEY,
    private_key BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at  TIMESTAMPTZ
);
