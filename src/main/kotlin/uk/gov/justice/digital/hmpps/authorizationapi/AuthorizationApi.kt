package uk.gov.justice.digital.hmpps.authorizationapi

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication()
class AuthorizationApi

fun main(args: Array<String>) {
  runApplication<AuthorizationApi>(*args)
}
