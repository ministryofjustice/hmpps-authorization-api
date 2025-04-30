plugins {
  id("uk.gov.justice.hmpps.gradle-spring-boot") version "8.1.0"
  kotlin("plugin.spring") version "2.1.20"
  kotlin("plugin.jpa") version "2.1.20"
}

configurations {
  testImplementation { exclude(group = "org.junit.vintage") }
}

dependencies {
  implementation("org.springframework.boot:spring-boot-starter-data-jpa")
  implementation("org.springframework.boot:spring-boot-starter-oauth2-client")
  implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")
  implementation("org.springframework.boot:spring-boot-starter-security")
  implementation("org.springframework.boot:spring-boot-starter-web")
  implementation("org.springframework.boot:spring-boot-starter-webflux")
  implementation("org.springframework.security:spring-security-oauth2-authorization-server")
  implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
  implementation("org.flywaydb:flyway-core")
  implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.8.6")
  implementation("org.json:json:20250107")
  implementation("commons-codec:commons-codec")
  implementation("org.apache.commons:commons-text:1.13.1")
  implementation("io.opentelemetry:opentelemetry-api")
  implementation("io.jsonwebtoken:jjwt:0.12.6")
  implementation("net.javacrumbs.shedlock:shedlock-spring:6.4.0")
  implementation("net.javacrumbs.shedlock:shedlock-provider-jdbc-template:6.4.0")

  runtimeOnly("com.h2database:h2:2.3.232")
  runtimeOnly("org.postgresql:postgresql:42.7.5")
  runtimeOnly("org.flywaydb:flyway-database-postgresql")
  developmentOnly("org.springframework.boot:spring-boot-devtools")

  testImplementation("org.springframework.boot:spring-boot-starter-webflux")
  testImplementation("io.jsonwebtoken:jjwt-impl:0.12.6")
  testImplementation("io.jsonwebtoken:jjwt-jackson:0.12.6")
  implementation(kotlin("stdlib"))
}

java {
  toolchain.languageVersion.set(JavaLanguageVersion.of(21))
}

tasks {
  withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    kotlinOptions {
      compilerOptions.jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21
    }
  }
}
