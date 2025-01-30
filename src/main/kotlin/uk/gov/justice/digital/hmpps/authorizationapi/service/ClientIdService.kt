package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.Client
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientRepository

@Component
class ClientIdService(private val clientRepository: ClientRepository) {
  private val clientIdSuffixRegex = "-[0-9]*$".toRegex()

  fun toBase(clientId: String) = clientId.replace(regex = clientIdSuffixRegex, replacement = "")

  fun clientNumber(clientId: String) = clientId.substringAfterLast("-").toIntOrNull() ?: 0

  fun findByBaseClientId(clientId: String): List<Client> {
    val searchClientId = toBase(clientId)
    return clientRepository.findByClientIdStartsWithOrderByClientId(searchClientId)
      .filter { it.clientId == searchClientId || it.clientId.substringAfter(searchClientId).matches(clientIdSuffixRegex) }
  }

  fun incrementClientId(clientId: String): String {
    val clients = findByBaseClientId(clientId)
    val baseClientId = toBase(clientId)
    if (clients.size > 2) {
      throw MaxDuplicateClientsException(baseClientId)
    }

    val clientIds = clients.map { clientNumber(it.clientId) }
    val increment = clientIds.maxOrNull()?.plus(1)
    return "$baseClientId-$increment"
  }
}

class MaxDuplicateClientsException(baseClientId: String) : RuntimeException("Unable to create further clients for baseClientId: $baseClientId as maximum of 3 already reached")
