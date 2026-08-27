-- Mastodon Client API OAuth.
--
-- Separate tables from the Solid-OIDC ones rather than a shared "oauth" schema
-- with a protocol column. The two protocols disagree about nearly everything
-- that matters here — Mastodon issues client secrets and non-expiring bearer
-- tokens, Solid issues neither — so a shared table would be half-null in both
-- directions and every query would carry a discriminator. ADR 0008 already
-- decided the surfaces stay separate; this is the storage consequence.
--
-- Secrets are stored hashed throughout: a database read must not yield a
-- usable credential.

CREATE TABLE mastodon_apps (
    client_id          TEXT PRIMARY KEY,
    -- Mastodon apps *do* get a secret, unlike the browser apps Solid
    -- registers. Confidential clients are the norm there.
    client_secret_hash TEXT NOT NULL,
    name               TEXT NOT NULL,
    redirect_uris      TEXT[] NOT NULL,
    scopes             TEXT NOT NULL,
    website            TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE mastodon_auth_codes (
    code_hash      TEXT PRIMARY KEY,
    client_id      TEXT NOT NULL REFERENCES mastodon_apps(client_id) ON DELETE CASCADE,
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri   TEXT NOT NULL,
    scopes         TEXT NOT NULL,
    -- PKCE is optional here, unlike Solid. Mastodon added it in 4.3 and older
    -- clients still authenticate without it, so refusing them would be
    -- refusing most of the ecosystem.
    code_challenge TEXT,
    expires_at     TIMESTAMPTZ NOT NULL,
    used_at        TIMESTAMPTZ
);

-- Access tokens. Mastodon's do not expire by default, and clients rely on
-- that — they store one and use it for years. Revocation is explicit.
CREATE TABLE mastodon_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id  TEXT NOT NULL REFERENCES mastodon_apps(client_id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scopes     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX mastodon_tokens_user_idx ON mastodon_tokens (user_id);
