plugins {
  id("uk.gov.justice.hmpps.gradle-spring-boot") version "5.1.3"
  kotlin("plugin.spring") version "1.8.21"
  kotlin("plugin.jpa") version "1.8.21"
  kotlin("jvm") version "1.8.21"
}

configurations {
  testImplementation { exclude(group = "org.junit.vintage") }
}

repositories {
  maven { url = uri("https://repo.spring.io/milestone") }
  mavenCentral()
}
dependencies {
  implementation("org.springframework.boot:spring-boot-starter-security")
  implementation("org.springframework.boot:spring-boot-starter-web")
  implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
  implementation("org.springframework.security:spring-security-oauth2-authorization-server:1.0.2")

  implementation("org.flywaydb:flyway-core:9.18.0")
  implementation("org.springframework.boot:spring-boot-starter-data-jpa")
  implementation("org.hibernate:hibernate-core:6.2.2.Final")

  implementation("commons-codec:commons-codec")

  runtimeOnly("com.h2database:h2:2.1.214")
  runtimeOnly("org.postgresql:postgresql:42.6.0")
  developmentOnly("org.springframework.boot:spring-boot-devtools")

  testImplementation("org.springframework.boot:spring-boot-starter-webflux")
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
