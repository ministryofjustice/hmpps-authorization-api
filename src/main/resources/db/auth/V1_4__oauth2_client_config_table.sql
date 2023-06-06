CREATE TABLE oauth2_client_config
(
    base_client_id  varchar(100) NOT NULL
        CONSTRAINT oauth2_client_config_pk
            PRIMARY KEY,
    allowed_ips     varchar(1000),
    client_end_date date
);