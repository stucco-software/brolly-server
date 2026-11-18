-- The session's client-key binding (stage 2, F).
--
-- A confidential client's assertion is signed by a key in its JWKS, and the
-- key's thumbprint (`client_jkt`) is stored with the pushed request and copied
-- to the code and the tokens: the session is bound to the client key, so the
-- same key must re-appear at the token endpoint and a refresh notices when it
-- has left the client's JWKS. NULL for a public client's session.
ALTER TABLE atproto_par_requests ADD COLUMN client_jkt TEXT;
ALTER TABLE atproto_auth_codes ADD COLUMN client_jkt TEXT;
ALTER TABLE atproto_tokens ADD COLUMN client_jkt TEXT;
