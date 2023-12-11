plugins {
  id("uk.gov.justice.hmpps.gradle-spring-boot") version "5.7.0"
  kotlin("plugin.spring") version "1.9.20"
  kotlin("plugin.jpa") version "1.9.20"
}

configurations {
  testImplementation { exclude(group = "org.junit.vintage") }
}

dependencies {
  implementation("org.springframework.boot:spring-boot-starter-security")
  implementation("org.springframework.boot:spring-boot-starter-web")
  implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
  implementation("org.springframework.security:spring-security-oauth2-authorization-server:1.1.3")

  implementation("org.flywaydb:flyway-core:9.22.3")
  implementation("org.springframework.boot:spring-boot-starter-data-jpa")
  implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.2.0")
  implementation("org.hibernate:hibernate-core:6.3.1.Final")

  implementation("commons-codec:commons-codec")
  implementation("org.apache.commons:commons-text:1.10.0")
  implementation("io.opentelemetry:opentelemetry-api")

  runtimeOnly("com.h2database:h2:2.2.224")
  runtimeOnly("org.postgresql:postgresql:42.6.0")
  developmentOnly("org.springframework.boot:spring-boot-devtools")

  testImplementation("org.springframework.boot:spring-boot-starter-webflux")
  testImplementation("io.jsonwebtoken:jjwt-impl:0.12.3")
  testImplementation("io.jsonwebtoken:jjwt-jackson:0.12.3")
  implementation(kotlin("stdlib"))
}

java {
  toolchain.languageVersion.set(JavaLanguageVersion.of(21))
}

tasks {
  withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    kotlinOptions {
      jvmTarget = "21"
    }
  }
}
