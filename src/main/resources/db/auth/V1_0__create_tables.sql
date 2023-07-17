CREATE TABLE oauth2_authorization
(
    id                            varchar(100) NOT NULL,
    registered_client_id          varchar(100) NOT NULL,
    principal_name                varchar(200) NOT NULL,
    authorization_grant_type      varchar(100) NOT NULL,
    authorized_scopes             varchar(1000) DEFAULT NULL,
    attributes                    text          DEFAULT NULL,
    state                         varchar(500)  DEFAULT NULL,
    authorization_code_value      text          DEFAULT NULL,
    authorization_code_issued_at  timestamp     DEFAULT NULL,
    authorization_code_expires_at timestamp     DEFAULT NULL,
    authorization_code_metadata   text          DEFAULT NULL,
    access_token_value            text          DEFAULT NULL,
    access_token_issued_at        timestamp     DEFAULT NULL,
    access_token_expires_at       timestamp     DEFAULT NULL,
    access_token_metadata         text          DEFAULT NULL,
    access_token_type             varchar(100)  DEFAULT NULL,
    access_token_scopes           varchar(1000) DEFAULT NULL,
    oidc_id_token_value           text          DEFAULT NULL,
    oidc_id_token_issued_at       timestamp     DEFAULT NULL,
    oidc_id_token_expires_at      timestamp     DEFAULT NULL,
    oidc_id_token_metadata        text          DEFAULT NULL,
    refresh_token_value           text          DEFAULT NULL,
    refresh_token_issued_at       timestamp     DEFAULT NULL,
    refresh_token_expires_at      timestamp     DEFAULT NULL,
    refresh_token_metadata        text          DEFAULT NULL,
    user_code_value               text          DEFAULT NULL,
    user_code_issued_at           timestamp     DEFAULT NULL,
    user_code_expires_at          timestamp     DEFAULT NULL,
    oauth2_authorization          text          DEFAULT NULL,
    device_code_value             text          DEFAULT NULL,
    device_code_issued_at         timestamp     DEFAULT NULL,
    device_code_expires_at        timestamp     DEFAULT NULL,
    device_code_metadata          text          DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE oauth2_authorization_consent
(
    registered_client_id varchar(100)  NOT NULL,
    principal_name       varchar(200)  NOT NULL,
    authorities          varchar(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);

CREATE TABLE oauth2_registered_client
(
    id                            varchar(100)                            NOT NULL,
    client_id                     varchar(100)                            NOT NULL,
    client_id_issued_at           timestamp     DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret                 varchar(200)  DEFAULT NULL,
    client_secret_expires_at      timestamp     DEFAULT NULL,
    client_name                   varchar(200)                            NOT NULL,
    client_authentication_methods varchar(1000)                           NOT NULL,
    authorization_grant_types     varchar(1000)                           NOT NULL,
    redirect_uris                 varchar(1000) DEFAULT NULL,
    scopes                        varchar(1000)                           NOT NULL,
    client_settings               varchar(2000)                           NOT NULL,
    token_settings                varchar(2000)                           NOT NULL,
    post_logout_redirect_uris     varchar(1000) DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE oauth2_client_config
(
    base_client_id                varchar(100)                            NOT NULL,
    allowed_ips                   varchar(1000) DEFAULT NULL,
    client_end_date               date          DEFAULT NULL,
    PRIMARY KEY (base_client_id)
);

CREATE TABLE oauth2_client_deployment_details
(
    base_client_id                varchar(100)                            NOT NULL,
    client_type                   varchar(255)  DEFAULT NULL,
    team                          varchar(255)  DEFAULT NULL,
    team_contact                  varchar(255)  DEFAULT NULL,
    team_slack                    varchar(255)  DEFAULT NULL,
    hosting                       varchar(255)  DEFAULT NULL,
    namespace                     varchar(255)  DEFAULT NULL,
    deployment                    varchar(255)  DEFAULT NULL,
    secret_name                   varchar(255)  DEFAULT NULL,
    client_id_key                 varchar(255)  DEFAULT NULL,
    secret_key                    varchar(255)  DEFAULT NULL,
    deployment_info               varchar(1000) DEFAULT NULL,
    PRIMARY KEY (base_client_id)
);

-- NOTE, the users and authorities tables below can be restructured as necessary
-- Doing so requires exposing a bean implementing UserDetailsService interface
CREATE TABLE users
(
    username varchar(50) NOT NULL PRIMARY KEY,
    password varchar(200) NOT NULL,
    enabled  boolean NOT NULL
);

CREATE TABLE authorities
(
    username  varchar(50) NOT NULL,
    authority varchar(50) NOT NULL,
    CONSTRAINT fk_authorities_users FOREIGN KEY (username) REFERENCES users (username)
);

CREATE UNIQUE INDEX ix_auth_username ON authorities (username, authority);