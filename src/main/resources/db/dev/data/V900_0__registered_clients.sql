INSERT INTO oauth2_registered_client
    (ID, CLIENT_ID, CLIENT_ID_ISSUED_AT, CLIENT_SECRET, CLIENT_SECRET_EXPIRES_AT, CLIENT_NAME,
     CLIENT_AUTHENTICATION_METHODS, AUTHORIZATION_GRANT_TYPES, REDIRECT_URIS, SCOPES, CLIENT_SETTINGS, TOKEN_SETTINGS, RESOURCE_IDS, SKIP_TO_AZURE, POST_LOGOUT_REDIRECT_URIS)

VALUES
    ('ceab6c18-081b-44e9-8130-3b37a254108f', 'test-client-id', current_timestamp, '{bcrypt}$2a$10$iItP8qu7ocHyw92687SKAehZQb7MhCjU6g37OGUt1I0guEE7B.4ba', null, 'test-client-1',
     'client_secret_basic', 'client_credentials', 'http://127.0.0.1:8089/authorized,https://oauth.pstmn.io/v1/callback', 'read,write',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":false,"settings.client.additional-data.jira-number":"HAAR-9999","settings.client.additional-data.database-user-name":"testy-db"}',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",1200.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",600.000000000]}',null, false, null),

    ('83c3869b-696d-4a6e-8da4-3d36666bab9d', 'test-client-create-id', current_timestamp, '{bcrypt}$2a$10$iItP8qu7ocHyw92687SKAehZQb7MhCjU6g37OGUt1I0guEE7B.4ba', null, 'test-client-2',
     'client_secret_basic', 'client_credentials', 'http://127.0.0.1:8089/authorized,https://oauth.pstmn.io/v1/callback', 'client.create',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":false}',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",1200.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",600.000000000]}',null, false, null),

    ('34dde3b1-15a1-4a19-8342-912b76d53727', 'ip-allow-a-client-1', current_timestamp, '{bcrypt}$2a$10$iItP8qu7ocHyw92687SKAehZQb7MhCjU6g37OGUt1I0guEE7B.4ba', null, 'ip-allow-a-client',
     'client_secret_basic', 'client_credentials', 'http://127.0.0.1:8089/authorized,https://oauth.pstmn.io/v1/callback', 'read,write',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":false}',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",1200.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",600.000000000]}', null, false, null),

    ('2eeaaa92-df65-4110-9b9f-20178f65bd0c', 'ip-allow-b-client', current_timestamp, '{bcrypt}$2a$10$iItP8qu7ocHyw92687SKAehZQb7MhCjU6g37OGUt1I0guEE7B.4ba', null, 'ip-allow-b-client',
     'client_secret_basic', 'client_credentials', 'http://127.0.0.1:8089/authorized,https://oauth.pstmn.io/v1/callback', 'read',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":false}',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",1200.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",600.000000000]}', null, false, null),

    ('ca9a884f-c7e2-4041-ae11-fda410a4f0be', 'ip-allow-b-client-8', current_timestamp, '{bcrypt}$2a$10$iItP8qu7ocHyw92687SKAehZQb7MhCjU6g37OGUt1I0guEE7B.4ba', null, 'ip-allow-b-client-8',
     'client_secret_basic', 'client_credentials', 'http://127.0.0.1:8089/authorized,https://oauth.pstmn.io/v1/callback', 'read',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":false}',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",1200.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",600.000000000]}', null, false, null),

    ('ceab6c18-081b-44e9-8130-3b37a254108g', 'test-duplicate-id', current_timestamp, '{bcrypt}$2a$10$iItP8qu7ocHyw92687SKAehZQb7MhCjU6g37OGUt1I0guEE7B.4ba', null, 'test-duplicate-1',
     'client_secret_basic', 'client_credentials', 'http://127.0.0.1:8089/authorized,https://oauth.pstmn.io/v1/callback', 'read,write',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":false,"settings.client.additional-data.jira-number":"HAAR-9999","settings.client.additional-data.database-user-name":"testy-db"}',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",1200.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",600.000000000]}',null, true, null),

    ('ceab6c18-081b-44e9-8130-3b37a254108z', 'test-complete-details-id', current_timestamp, '{bcrypt}$2a$10$iItP8qu7ocHyw92687SKAehZQb7MhCjU6g37OGUt1I0guEE7B.4ba', null, 'test-complete-details-id',
     'client_secret_basic', 'client_credentials', 'http://127.0.0.1:8089/authorized,https://oauth.pstmn.io/v1/callback', 'read,write',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":false,"settings.client.additional-data.jira-number":"HAAR-9999","settings.client.additional-data.database-user-name":"testy-db"}',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",1200.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",600.000000000]}',null, false, null),

    ('4201e0c6-157b-4cdc-8da2-ffceefbacbc5', 'ip-allow-c-client', current_timestamp, '{bcrypt}$2a$10$iItP8qu7ocHyw92687SKAehZQb7MhCjU6g37OGUt1I0guEE7B.4ba', null, 'ip-allow-c-client',
     'client_secret_basic', 'client_credentials', 'http://127.0.0.1:8089/authorized,https://oauth.pstmn.io/v1/callback', 'read',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":false}',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",1200.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",600.000000000]}', null, false, null),

    ('05ac35b9-ef9d-47c3-9409-cbcf334acd73', 'test-auth-code-client', current_timestamp, '{bcrypt}$2a$10$iItP8qu7ocHyw92687SKAehZQb7MhCjU6g37OGUt1I0guEE7B.4ba', null, 'test-client-1',
     'client_secret_basic', 'authorization_code', 'http://127.0.0.1:8089/login/oauth2/code/oidc-client,https://oauth.pstmn.io/v1/callback', 'read',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":false}',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.authorization-code-time-to-live":["java.time.Duration",1200.000000000],"settings.token.additional-data.jira-number":"HAAR-9999","settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"}}',
     null, false,'http://127.0.0.1:8089/'),

    ('05ac35b9-ef9d-47c3-9409-cbcf334acd74', 'test-auth-code-client-with-jwt-settings', current_timestamp, '{bcrypt}$2a$10$iItP8qu7ocHyw92687SKAehZQb7MhCjU6g37OGUt1I0guEE7B.4ba', null, 'test-auth-code-client-with-jwt-settings',
     'client_secret_basic', 'authorization_code', 'http://127.0.0.1:8089/login/oauth2/code/oidc-client,https://oauth.pstmn.io/v1/callback', 'read',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":false,"settings.client.additional-data.jwtFields":"user_name,user_id"}',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.authorization-code-time-to-live":["java.time.Duration",1200.000000000],"settings.token.additional-data.jira-number":"HAAR-9999","settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"}}',
     null, false,'http://127.0.0.1:8089/'),

    ('ceab6c18-081b-44e9-8130-3b37a2541089', 'hmpps-auth-authorization-api-client', current_timestamp, '{bcrypt}$2a$10$KeuHCVZ4DmBiaM6zvy9OzO2Ze/zFkCc9DrHSHq9Y8LiP0o3ZIHk9S', null, 'hmpps-auth-authorization-api-client',
     'client_secret_basic', 'client_credentials', 'http://127.0.0.1:8089/authorized,https://oauth.pstmn.io/v1/callback', 'read,write',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":false,"settings.client.additional-data.jira-number":"HAAR-9999","settings.client.additional-data.database-user-name":"testy-db"}',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",1200.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",600.000000000]}',null, false, null);

INSERT INTO oauth2_client_config (base_client_id, allowed_ips)
VALUES
       ('ip-allow-a-client', '127.0.0.1/32'),
       ('ip-allow-b-client', '35.176.93.186'),
       ('ip-allow-c-client', '35.176.0.0/16');
