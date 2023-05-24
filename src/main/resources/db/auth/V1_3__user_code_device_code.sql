ALTER TABLE oauth2_authorization ADD COLUMN user_code_value text DEFAULT NULL;
ALTER TABLE oauth2_authorization ADD COLUMN user_code_issued_at timestamp DEFAULT NULL;
ALTER TABLE oauth2_authorization ADD COLUMN user_code_expires_at timestamp DEFAULT NULL;
ALTER TABLE oauth2_authorization ADD COLUMN user_code_metadata text DEFAULT NULL;

ALTER TABLE oauth2_authorization ADD COLUMN device_code_value text DEFAULT NULL;
ALTER TABLE oauth2_authorization ADD COLUMN device_code_issued_at timestamp DEFAULT NULL;
ALTER TABLE oauth2_authorization ADD COLUMN device_code_expires_at timestamp DEFAULT NULL;
ALTER TABLE oauth2_authorization ADD COLUMN device_code_metadata text DEFAULT NULL;
