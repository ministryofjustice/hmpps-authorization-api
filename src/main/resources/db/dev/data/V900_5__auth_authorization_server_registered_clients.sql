INSERT INTO oauth2_registered_client
(ID, CLIENT_ID, CLIENT_ID_ISSUED_AT, CLIENT_SECRET, CLIENT_SECRET_EXPIRES_AT, CLIENT_NAME,
 CLIENT_AUTHENTICATION_METHODS, AUTHORIZATION_GRANT_TYPES, REDIRECT_URIS, SCOPES, CLIENT_SETTINGS, TOKEN_SETTINGS)
VALUES ('ceab6c18-081b-44e9-8130-3b37a2541089', 'hmpps-auth-authorization-api-client', current_timestamp, '{bcrypt}$2a$10$KeuHCVZ4DmBiaM6zvy9OzO2Ze/zFkCc9DrHSHq9Y8LiP0o3ZIHk9S', null, 'hmpps-auth-authorization-api-client',
        'client_secret_basic', 'client_credentials', 'http://127.0.0.1:8089/authorized,https://oauth.pstmn.io/v1/callback', 'read,write',
        '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":false}',
        '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",600.000000000],"settings.token.additional-data.jira-number":"HAAR-9999","settings.token.additional-data.database-user-name":"testy-db"}');


INSERT INTO oauth2_authorization_consent(registered_client_id, principal_name, authorities) VALUES
    ('ceab6c18-081b-44e9-8130-3b37a2541089', 'hmpps-auth-authorization-api-client', 'ROLE_OAUTH_ADMIN,ROLE_AUDIT,ROLE_TESTING,ROLE_OAUTH_CLIENTS_VIEW');
