-- WebID links and client_credentials for linked WebIDs (ADR 0020) — the
-- CSS model: an account links a WebID (typically one this instance does not
-- host, whose own document names this issuer), then id/secret pairs are
-- minted against the link, and client_credentials tokens name the WebID.
--
-- Secrets are stored hashed throughout, for the same reason as sessions: a
-- database read must not yield a usable credential.

-- A WebID linked to an account. One WebID, one account: the link is the
-- WebID's delegation of its identity to this issuer, and one identity has
-- one owner here. The dereference that proves the WebID's side (its
-- `solid:oidcIssuer` naming this issuer) happens before the write — see
-- `brolly_server::solid_oidc::link_webid`.
CREATE TABLE solid_webid_links (
    webid      TEXT PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX solid_webid_links_user_idx ON solid_webid_links (user_id);

-- client_credentials id/secret pairs (RFC 6749 §4.4), each naming one linked
-- WebID. The unlink is the kill switch: removing the link cascades to every
-- credential minted for it, so a compromised WebID's tokens stop at the
-- unlink rather than at the expiry of the last access token.
CREATE TABLE solid_client_credentials (
    credential_id TEXT PRIMARY KEY,
    secret_hash   TEXT NOT NULL,
    webid         TEXT NOT NULL REFERENCES solid_webid_links(webid) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ
);

CREATE INDEX solid_client_credentials_webid_idx ON solid_client_credentials (webid);
