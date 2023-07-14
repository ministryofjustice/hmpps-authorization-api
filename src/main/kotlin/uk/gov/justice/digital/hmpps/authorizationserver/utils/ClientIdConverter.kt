package uk.gov.justice.digital.hmpps.authorizationserver.utils

import org.springframework.stereotype.Component

@Component
class ClientIdConverter {
  private val clientIdSuffixRegex = "-[0-9]*$".toRegex()

  fun toBase(clientId: String) = clientId.replace(regex = clientIdSuffixRegex, replacement = "")
}
