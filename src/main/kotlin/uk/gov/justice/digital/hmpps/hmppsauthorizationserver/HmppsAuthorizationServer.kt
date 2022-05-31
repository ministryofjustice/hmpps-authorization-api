package uk.gov.justice.digital.hmpps.hmppsauthorizationserver

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication()
class HmppsAuthorizationServer

fun main(args: Array<String>) {
  runApplication<HmppsAuthorizationServer>(*args)
}
