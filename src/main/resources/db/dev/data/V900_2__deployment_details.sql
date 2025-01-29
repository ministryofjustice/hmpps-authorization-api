INSERT INTO oauth2_client_deployment_details
(BASE_CLIENT_ID, CLIENT_TYPE, TEAM, TEAM_CONTACT, TEAM_SLACK, HOSTING, NAMESPACE, DEPLOYMENT, SECRET_NAME, CLIENT_ID_KEY, SECRET_KEY, DEPLOYMENT_INFO)
VALUES
    ('test-client-id', 'PERSONAL', 'HAAR', 'Testy McTester', '#hmpps-auth-audit-registers', 'CLOUDPLATFORM',
     'hmpps-audit-dev', 'hmpps-audit-dev', 'AUDIT_SECRET', 'AUDIT_API_KEY',
     'AUDIT_SECRET_KEY', null),
    ('test-client-create-id', 'PERSONAL', 'HAAR', 'Testy McTester', '#hmpps-auth-audit-registers', 'CLOUDPLATFORM',
     'hmpps-audit-dev', 'hmpps-audit-dev', 'AUDIT_SECRET', 'AUDIT_API_KEY',
     'AUDIT_SECRET_KEY', null);

-- Dev data from Auth --

INSERT INTO oauth2_client_deployment_details (base_client_id, client_type, team, team_contact, team_slack, hosting, namespace, deployment, secret_name, client_id_key, secret_key, deployment_info)
VALUES  ('another-delete-test-client', 'SERVICE', 'A Team', 'A Team contact', 'A team slack', 'CLOUDPLATFORM', 'another-delete-test-dev', 'another-delete-test-deployment', 'another-delete-test-secret', 'API_CLIENT_ID', 'API_CLIENT_SECRET', 'More info blah'),
        ('individual-client', 'PERSONAL', 'Bob', 'Bob@digital.justice.gov.uk', 'bob slack', 'OTHER', null, null, null, null, null, null),
        ('service-client', 'SERVICE', 'A Team', 'A Team contact', 'A team slack', 'CLOUDPLATFORM', 'service-dev', 'service-deployment', 'service-secret', 'API_CLIENT_ID', 'API_CLIENT_SECRET', 'More info blah'),
        ('another-test-client', 'SERVICE', 'A Team', 'A Team contact', 'A team slack', 'CLOUDPLATFORM', 'duplicate-dev', 'duplicate-deployment', 'duplicate-secret', 'API_CLIENT_ID', 'API_CLIENT_SECRET', 'More info blah');
