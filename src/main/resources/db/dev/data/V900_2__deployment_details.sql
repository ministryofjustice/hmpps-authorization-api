INSERT INTO oauth2_client_deployment_details
(BASE_CLIENT_ID, CLIENT_TYPE, TEAM, TEAM_CONTACT, TEAM_SLACK, HOSTING, NAMESPACE, DEPLOYMENT, SECRET_NAME, CLIENT_ID_KEY, SECRET_KEY, DEPLOYMENT_INFO)
VALUES
    ('test-client-id', 'PERSONAL', 'HAAR', 'Testy McTester', '#hmpps-auth-audit-registers', 'CLOUDPLATFORM',
     'hmpps-audit-dev', 'hmpps-audit-dev', 'AUDIT_SECRET', 'AUDIT_API_KEY',
     'AUDIT_SECRET_KEY', null),
    ('test-client-create-id', 'PERSONAL', 'HAAR', 'Testy McTester', '#hmpps-auth-audit-registers', 'CLOUDPLATFORM',
     'hmpps-audit-dev', 'hmpps-audit-dev', 'AUDIT_SECRET', 'AUDIT_API_KEY',
     'AUDIT_SECRET_KEY', null);
