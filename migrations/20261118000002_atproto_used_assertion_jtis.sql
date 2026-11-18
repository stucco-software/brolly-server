-- Every client assertion's jti, so an assertion is accepted once (stage 2, F).
--
-- Keyed on (jkt, jti), not jti alone — the dpop_jti shape (S7): the client
-- picks the jti, and one key's choice must not get another's assertions
-- refused.
--
-- A row only has to outlive its assertion's freshness window, iat + 60 s.
-- `UnspentAssertion::spend` (adapters/atproto/src/client_assertion.rs) prunes
-- expired rows in the same statement that inserts, by the application's clock
-- — the dpop_jti rule, since that is the clock that decides freshness. There
-- is no background job.
CREATE TABLE atproto_used_assertion_jtis (
    jkt        TEXT        NOT NULL,
    jti        TEXT        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (jkt, jti)
);

CREATE INDEX atproto_used_assertion_jtis_expires
    ON atproto_used_assertion_jtis (expires_at);
