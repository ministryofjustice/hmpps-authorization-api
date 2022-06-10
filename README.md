# HMPPS Authorization Server

Spring Boot 2.7, Java 17, Spring Security Authorization Server covering the client credentials flow. This project has been started with the intention of:
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

### Run locally against a Postgres database
By default, Authorization Server runs against an in memory h2 database.  It can be run against a local Postgres database too, useful
to verify database related changes prior to test environment deployment.

Steps are:

* Run a local docker container to start up authorization-server-db only (see docker-compose-test.yml)
* Set the appropriate spring profiles: SPRING_ACTIVE_PROFILES=dev,local-postgres