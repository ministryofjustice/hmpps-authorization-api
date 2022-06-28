package uk.gov.justice.digital.hmpps.authorizationserver

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication()
class AuthorizationServer

fun main(args: Array<String>) {
  runApplication<AuthorizationServer>(*args)
}
