-- Every DPoP proof's jti, so a proof is accepted once (RFC 9449).
--
-- Keyed on (jkt, jti), not jti alone. The client picks the jti, and one client's
-- choice must not get another client's proofs refused.
--
-- A row only has to outlive its proof's freshness window, iat + MAX_AGE_SECONDS.
-- `Unspent::spend` (identity/src/dpop.rs) prunes expired rows in the same
-- statement that inserts. It uses the application's clock, not now(), because
-- that is the clock that decides freshness. There is no background job.
CREATE TABLE dpop_jti (
    jkt        TEXT        NOT NULL,
    jti        TEXT        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (jkt, jti)
);
CREATE INDEX dpop_jti_expires ON dpop_jti (expires_at);
