# HMPPS Authorization API

Spring Boot 3.2.0, Java 21, Spring Security Authorization API covering the client credentials flow. This project has been started with the intention of:
- Moving HMPPS Auth off the deprecated spring-security-oauth2 library
- Simplifying Auth by splitting out client credentials flows into a separate service

At this stage it is simply a proof of concept, with an initial target of being capable of issuing a usable client credentials token within the dev environment.

### Code style & formatting
```bash
./gradlew ktlintApplyToIdea addKtlintFormatGitPreCommitHook
```
will apply ktlint styles to intellij and also add a pre-commit hook to format all changed kotlin files.

### Run locally on the command line
```bash
SPRING_PROFILES_ACTIVE=dev ./gradlew bootRun
```

The service should start up using the dev profile, perform the flyway migrations on a local HSQLDB and then seed local development data.

When running locally with SPRING_ACTIVE_PROFILES=dev the seeded H2 database console is available at http://localhost:8080/authorization-api-db/h2-console

| Database                | JDBC connection                     | username  | password  |
|-------------------------|-------------------------------------|-----------|-----------|
| authorization-api-db | jdbc:h2:mem:authorization-api-db | `<blank>` | `<blank>` |


### Run locally against a Postgres database
By default, Authorization API runs against an in memory h2 database.  It can be run against a local Postgres database too, useful
to verify database related changes prior to test environment deployment.

Steps are:

* Run a local docker container to start up authorization-api-db only (use either docker-compose-test.yml from within your IDE or command below)
* Start authorization-api with the appropriate spring profiles: SPRING_ACTIVE_PROFILES=dev,local-postgres

```
docker stop authorization-api-db && docker rm authorization-api-db && docker-compose -f docker-compose-test.yml up
```

### Testing locally

Authorization API runs locally on port 8089.

After starting the application locally, the client credentials flow can be tested via Postman, using the following variables:

```bash
client-id=test-client-id
client-secret=test-secret
access-token-url=http://localhost:8089/oauth2/token
auth-url=http://localhost:8089/
```

The generated token can be de-coded at jwt.io

The authorization code flow is also supported and can be tested via Postman using the following variables:

```bash
client-id=test-client-id
client-secret=test-secret
access-token-url=http://localhost:8089/oauth2/token
auth-url=http://localhost:8089/oauth2/authorize
```

Note that for this flow you will also need to check the 'authorize using browser' checkbox in Postman. When presented with the login page use username: alant and password: letmein.
The generated token will live for 5 minutes so subsequent attempts to retrieve the token whilst there is already one live do not require re-authentication.

### Testing in DEV

To test the client credentials flow in the DEV environment, the only difference is the URLs (client-id and client-secret are the same). Use the following URLs:

```bash
access-token-url=https://authorization-api-dev.hmpps.service.justice.gov.uk/oauth2/token
auth-url=https://authorization-api-dev.hmpps.service.justice.gov.uk/
```
