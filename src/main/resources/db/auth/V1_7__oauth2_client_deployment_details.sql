CREATE TABLE oauth_client_deployment_details
(
    base_client_id  varchar(100) NOT NULL,
    client_type     varchar(255),
    team            varchar(255),
    team_contact    varchar(255),
    team_slack      varchar(255),
    hosting         varchar(255),
    namespace       varchar(255),
    deployment      varchar(255),
    secret_name     varchar(255),
    client_id_key   varchar(255),
    secret_key      varchar(255),
    deployment_info varchar(1000),
    PRIMARY KEY (base_client_id)
    );