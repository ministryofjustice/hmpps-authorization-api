ALTER TABLE oauth2_registered_client
    ADD COLUMN migrated_last_accessed timestamp DEFAULT NULL