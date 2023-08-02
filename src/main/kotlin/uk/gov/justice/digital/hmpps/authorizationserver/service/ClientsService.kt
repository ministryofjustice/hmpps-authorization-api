package uk.gov.justice.digital.hmpps.authorizationserver.service

import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.AuthorizationConsent
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.Client
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientConfig
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientDeployment
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientType
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.AuthorizationConsentRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientDeploymentRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientRepository
import uk.gov.justice.digital.hmpps.authorizationserver.utils.ClientIdService
import java.time.LocalDate

@Service
class ClientsService(
  private val clientRepository: ClientRepository,
  private val clientConfigRepository: ClientConfigRepository,
  private val authorizationConsentRepository: AuthorizationConsentRepository,
  private val clientIdService: ClientIdService,
  private val clientDeploymentRepository: ClientDeploymentRepository,
) {
  fun retrieveAllClients(): List<ClientSummary> {
    val baseClients = clientRepository.findAll().groupBy { clientIdService.toBase(it.clientId) }.toSortedMap()
    val configs = clientConfigRepository.findAll().associateBy { it.baseClientId }
    val deployments = clientDeploymentRepository.findAll().associateBy { it.baseClientId }
    val authorizationConsents = authorizationConsentRepository.findAll().associateBy { clientIdService.toBase(it.principalName) }

    return baseClients.toList().map { client ->
      val config: ClientConfig? = configs[client.first]
      val deployment: ClientDeployment? = deployments[client.first]
      val authorities: AuthorizationConsent? = authorizationConsents[client.first]
      val firstClient = client.second[0]
      val roles = authorities?.authoritiesWithoutPrefix?.sorted()?.joinToString("\n")
      ClientSummary(
        baseClientId = client.first,
        clientType = deployment?.clientType,
        teamName = deployment?.team,
        grantType = firstClient.authorizationGrantTypes,
        roles = roles,
        count = client.second.size,
        expired = if (config?.clientEndDate?.isBefore(LocalDate.now()) == true)"EXPIRED" else null,
      )
    }
  }

  @Transactional
  fun deleteClient(clientId: String) {
    val clientsByBaseClientId = clientIdService.findByBaseClientId(clientId)
    if (clientsByBaseClientId.isEmpty()) {
      throw ClientNotFoundException(Client::class.simpleName, clientId)
    }

    if (clientsByBaseClientId.size == 1) {
      val baseClientId = clientIdService.toBase(clientId)
      clientDeploymentRepository.deleteByBaseClientId(baseClientId)
      clientConfigRepository.deleteByBaseClientId(baseClientId)
    }

    clientRepository.deleteByClientId(clientId)
  }
}

data class ClientSummary(
  val baseClientId: String,
  val clientType: ClientType?,
  val teamName: String?,
  val grantType: String,
  val roles: String?,
  val count: Int,
  val expired: String?,
)

class ClientNotFoundException(entityName: String?, clientId: String) : RuntimeException("$entityName for client id $clientId not found")
