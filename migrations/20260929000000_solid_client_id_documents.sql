-- Client ID Documents (spec 6, H3): the third kind of client.
--
-- `solid_auth_codes` and `solid_refresh_tokens` carried a foreign key to
-- `solid_clients`, written when dynamic registration (RFC 7591) was the only
-- other client kind and every grant's client was a row in it. A Client ID
-- Document client is not: it is an `https://` URL fetched and validated at
-- authorize time, and the spec's design is that the grant remembers the
-- client_id *string* — the token endpoint's comparison is unchanged. The
-- foreign key made that insert impossible, so both become plain strings.
--
-- Nothing has ever deleted a `solid_clients` row, so the `ON DELETE CASCADE`
-- they carried was dormant; dropping it changes nothing for registered
-- clients. (The H4 consent table's `redirect_uris` column is what will keep a
-- remembered consent from outliving a changed client document; a foreign key
-- could never do that job, because there is nothing to point at.)

ALTER TABLE solid_auth_codes
    DROP CONSTRAINT solid_auth_codes_client_id_fkey;

ALTER TABLE solid_refresh_tokens
    DROP CONSTRAINT solid_refresh_tokens_client_id_fkey;
