-- A rotation key is a third purpose.
--
-- It has to be a separate key from the repo signing key, and a separate row:
-- the signing key signs every commit and is the one likelier to leak, so
-- recovery means replacing it with a key that was never in that path. Storing
-- one key under both purposes would make a compromise unrecoverable while
-- looking, from the schema, exactly like doing it properly.
ALTER TABLE user_keys DROP CONSTRAINT user_keys_purpose_check;
ALTER TABLE user_keys ADD CONSTRAINT user_keys_purpose_check
    CHECK (purpose IN ('atproto_signing', 'atproto_rotation', 'activitypub_rsa'));
