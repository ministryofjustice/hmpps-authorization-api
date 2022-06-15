INSERT INTO users(username, password, enabled) VALUES ('alant', '$2a$10$zkE9YjvII6P64bsgC/S4le0CL6AZWE5O64GARCcyJYA/PUWTPo2wO', true);

INSERT INTO authorities(username, authority) VALUES('alant', 'AUTH_GROUP_MANAGER'), ('alant', 'CENTRAL_ADMIN');