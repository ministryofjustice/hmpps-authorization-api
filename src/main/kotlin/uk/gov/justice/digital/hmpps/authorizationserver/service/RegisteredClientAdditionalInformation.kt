package uk.gov.justice.digital.hmpps.authorizationserver.service

import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationserver.resource.ClientCredentialsRegistrationRequest

@Component
class RegisteredClientAdditionalInformation {

  val jiraNumber = "jiraNumber"
  val databaseUserName = "databaseUserName"

  fun mapFrom(clientDetails: ClientCredentialsRegistrationRequest): Map<String, Any> {
    val additionalInformation = LinkedHashMap<String, Any>()
    clientDetails.jiraNumber?.let { additionalInformation[jiraNumber] = it }
    clientDetails.databaseUserName?.let { additionalInformation[databaseUserName] = it }
    return additionalInformation
  }

  fun mapFrom(claims: Map<String, Any>): Map<String, Any> {
    val additionalInformation = LinkedHashMap<String, Any>()
    claims[jiraNumber]?.let { additionalInformation[jiraNumber] = it }
    return additionalInformation
  }
}
