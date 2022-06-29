INSERT INTO oauth2_registered_client
    (ID, CLIENT_ID, CLIENT_ID_ISSUED_AT, CLIENT_SECRET, CLIENT_SECRET_EXPIRES_AT, CLIENT_NAME,
     CLIENT_AUTHENTICATION_METHODS, AUTHORIZATION_GRANT_TYPES, REDIRECT_URIS, SCOPES, CLIENT_SETTINGS, TOKEN_SETTINGS)
VALUES
    ('ceab6c18-081b-44e9-8130-3b37a254108f', 'test-client-id', current_timestamp, '$2a$10$iItP8qu7ocHyw92687SKAehZQb7MhCjU6g37OGUt1I0guEE7B.4ba', null, 'alan_t_testing',
     'client_secret_basic', 'refresh_token,client_credentials,authorization_code', 'http://127.0.0.1:8089/authorized,https://oauth.pstmn.io/v1/callback', 'read,write',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":false}',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.core.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",600.000000000]}');
