package uk.gov.justice.digital.hmpps.authorizationserver

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.scheduling.annotation.EnableScheduling

@SpringBootApplication()
@EnableScheduling
class AuthorizationServer

fun main(args: Array<String>) {
  runApplication<AuthorizationServer>(*args)
}
