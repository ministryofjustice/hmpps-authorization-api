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
import java.time.Instant
import java.time.LocalDate

@Service
class ClientsService(
  private val clientRepository: ClientRepository,
  private val clientConfigRepository: ClientConfigRepository,
  private val authorizationConsentRepository: AuthorizationConsentRepository,
  private val clientIdService: ClientIdService,
  private val clientDeploymentRepository: ClientDeploymentRepository,
) {
  fun retrieveAllClients(sortBy: SortBy, filterBy: ClientFilter?): List<ClientSummary> {
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
      val lastAccessed = client.second[0].getLastAccessedDate()
      val secretUpdated = client.second[0].clientIdIssuedAt
      ClientSummary(
        baseClientId = client.first,
        clientType = deployment?.clientType,
        teamName = deployment?.team,
        grantType = firstClient.authorizationGrantTypes,
        roles = roles,
        count = client.second.size,
        expired = if (config?.clientEndDate?.isBefore(LocalDate.now()) == true)"EXPIRED" else null,
        secretUpdated = secretUpdated,
        lastAccessed = lastAccessed,
      )
    }.filter { cs ->
      filterBy?.let { filter ->
        (filter.clientType == null || filter.clientType == cs.clientType) &&
          (filter.grantType.isNullOrBlank() || cs.grantType.contains(filter.grantType)) &&
          (filter.role.isNullOrBlank() || cs.roles?.contains(filter.role.uppercase()) ?: false)
      } ?: true
    }.sortedWith(
      compareBy {
        when (sortBy) {
          SortBy.TYPE -> it.clientType
          SortBy.TEAM -> it.teamName
          SortBy.COUNT -> it.count
          SortBy.LAST_ACCESSED -> it.lastAccessed
          SortBy.SECRET_UPDATED -> it.secretUpdated
          else -> it.baseClientId
        }
      },
    )
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

  fun findClientByClientId(clientId: String) =
    clientRepository.findClientByClientId(clientId)
      ?: throw ClientNotFoundException(Client::class.simpleName, clientId)
}

data class ClientSummary(
  val baseClientId: String,
  val clientType: ClientType?,
  val teamName: String?,
  val grantType: String,
  val roles: String?,
  val count: Int,
  val expired: String?,
  val secretUpdated: Instant?,
  val lastAccessed: Instant?,
)

class ClientNotFoundException(entityName: String?, clientId: String) : RuntimeException("$entityName for client id $clientId not found")

enum class SortBy {
  CLIENT, TYPE, TEAM, LAST_ACCESSED, SECRET_UPDATED, COUNT
}

data class ClientFilter(
  val grantType: String? = null,
  val role: String? = null,
  val clientType: ClientType? = null,
)
