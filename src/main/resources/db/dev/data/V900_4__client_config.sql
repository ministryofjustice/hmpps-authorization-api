INSERT INTO oauth2_client_config (base_client_id, allowed_ips, client_end_date)
VALUES
    ('ip-allow-a-client', '127.0.0.1/32', null),
    ('ip-allow-b-client', '35.176.93.186', null),
    ('ip-allow-c-client', '35.176.0.0/16', null),
    ('test-test', '35.176.0.0/16', null),
    ('test-one-instance', '35.176.0.0/16', null),
    ('expiry-test-client', '35.176.0.0/16', '2023-01-01');

-- Dev Data From Auth --

INSERT INTO oauth2_client_config (base_client_id, allowed_ips, client_end_date)
VALUES  ('end-date-client', '', null),
        ('expired-end-date-client', '', null),
        ('hmpps-audit-api-client', 'localhost,group-a', null),
        ('ip-allow-group-client', '35.176.0.0/16,group_name_a', null),
        ('service-client', '127.0.0.1', null),
        ('another-test-client', '127.0.0.1', null);

-- No authorities test --
insert into oauth2_client_config (base_client_id, allowed_ips, client_end_date)
values  ('no-authorities', '127.0.0.1', null);