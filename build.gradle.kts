plugins {
  id("uk.gov.justice.hmpps.gradle-spring-boot") version "4.2.0"
  kotlin("plugin.spring") version "1.6.21"
  kotlin("plugin.jpa") version "1.6.21"
}

configurations {
  testImplementation { exclude(group = "org.junit.vintage") }
}

dependencies {
  implementation("org.springframework.boot:spring-boot-starter-security")
  implementation("org.springframework.boot:spring-boot-starter-web")
  implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
  implementation("org.springframework.security:spring-security-oauth2-authorization-server:0.2.3")

  implementation("org.flywaydb:flyway-core:8.5.11")
  implementation("org.springframework.boot:spring-boot-starter-data-jpa")
  implementation("org.hibernate:hibernate-core:5.6.9.Final")

  runtimeOnly("com.h2database:h2:2.1.210")
  runtimeOnly("org.postgresql:postgresql:42.3.6")
  developmentOnly("org.springframework.boot:spring-boot-devtools")
}

java {
  toolchain.languageVersion.set(JavaLanguageVersion.of(17))
}

tasks {
  withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    kotlinOptions {
      jvmTarget = "17"
    }
  }
}
