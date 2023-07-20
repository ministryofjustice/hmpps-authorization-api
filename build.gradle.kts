plugins {
  id("uk.gov.justice.hmpps.gradle-spring-boot") version "5.2.0-beta"
  kotlin("plugin.spring") version "1.8.21"
  kotlin("plugin.jpa") version "1.8.21"
}

configurations {
  testImplementation { exclude(group = "org.junit.vintage") }
}

dependencies {
  implementation("org.springframework.boot:spring-boot-starter-security")
  implementation("org.springframework.boot:spring-boot-starter-web")
  implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
  implementation("org.springframework.security:spring-security-oauth2-authorization-server:1.1.0")

  implementation("org.flywaydb:flyway-core:9.19.0")
  implementation("org.springframework.boot:spring-boot-starter-data-jpa")
  implementation("org.hibernate:hibernate-core:6.2.3.Final")

  implementation("commons-codec:commons-codec")
  implementation("org.apache.commons:commons-text:1.10.0")
  implementation("io.opentelemetry:opentelemetry-api:1.27.0")

  runtimeOnly("com.h2database:h2:2.1.214")
  runtimeOnly("org.postgresql:postgresql:42.6.0")
  developmentOnly("org.springframework.boot:spring-boot-devtools")

  testImplementation("org.springframework.boot:spring-boot-starter-webflux")
  testImplementation("io.jsonwebtoken:jjwt-impl:0.11.5")
  testImplementation("io.jsonwebtoken:jjwt-jackson:0.11.5")
  implementation(kotlin("stdlib"))
}

java {
  toolchain.languageVersion.set(JavaLanguageVersion.of(19))
}

tasks {
  withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    kotlinOptions {
      jvmTarget = "19"
    }
  }
}
