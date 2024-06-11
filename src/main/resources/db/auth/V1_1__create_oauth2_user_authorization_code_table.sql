CREATE TABLE oauth2_user_authorization_code
(
    id                            varchar(100) NOT NULL primary key references oauth2_authorization,
    user_name                     varchar(100) DEFAULT NULL,
    user_id                       varchar(100) DEFAULT NULL,
    user_uuid                     varchar(100) DEFAULT NULL,
    name                          varchar(100) DEFAULT NULL,
    source                        varchar(50) DEFAULT NULL,
    authorization_code_issued_at  timestamp
);