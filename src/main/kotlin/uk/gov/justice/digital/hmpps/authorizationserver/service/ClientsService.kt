package uk.gov.justice.digital.hmpps.authorizationserver.service

import org.springframework.data.repository.findByIdOrNull
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.AuthorizationConsent
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.AuthorizationConsent.AuthorizationConsentId
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.Client
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientConfig
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientDeployment
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientType
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.AuthorizationConsentRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientDeploymentRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientRepository
import uk.gov.justice.digital.hmpps.authorizationserver.utils.OAuthClientSecret
import java.time.Instant
import java.time.LocalDate
import java.util.Base64.getEncoder

@Service
class ClientsService(
  private val clientRepository: ClientRepository,
  private val clientConfigRepository: ClientConfigRepository,
  private val authorizationConsentRepository: AuthorizationConsentRepository,
  private val clientIdService: ClientIdService,
  private val clientDeploymentRepository: ClientDeploymentRepository,
  private val registeredClientRepository: JdbcRegisteredClientRepository,
  private val oAuthClientSecret: OAuthClientSecret,
) {
  fun retrieveAllClients(sortBy: SortBy, filterBy: ClientFilter?): List<ClientDetail> {
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
      ClientDetail(
        baseClientId = client.first,
        clientType = deployment?.clientType,
        teamName = deployment?.team,
        grantType = firstClient.authorizationGrantTypes,
        roles = roles,
        count = client.second.size,
        expired = if (config?.clientEndDate?.isBefore(LocalDate.now()) == true)"EXPIRED" else null,
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

  fun findClientWithCopies(clientId: String): List<Client> {
    val clients = clientIdService.findByBaseClientId(clientId)
    if (clients.isEmpty()) {
      throw ClientNotFoundException(Client::class.simpleName, clientId)
    }
    return clients
  }

  fun findClientByClientId(clientId: String) =
    clientRepository.findClientByClientId(clientId)
      ?: throw ClientNotFoundException(Client::class.simpleName, clientId)

  @Transactional
  fun duplicate(clientId: String): DuplicateRegistrationResponse {
    val clientsByBaseClientId = clientIdService.findByBaseClientId(clientId)
    if (clientsByBaseClientId.isEmpty()) {
      throw ClientNotFoundException(Client::class.simpleName, clientId)
    }

    val client = clientsByBaseClientId.last()
    val registeredClient = registeredClientRepository.findByClientId(client.clientId)
    val registeredClientBuilder = RegisteredClient.from(registeredClient)

    val externalClientSecret = oAuthClientSecret.generate()
    val duplicatedRegisteredClient = registeredClientBuilder
      .id(java.util.UUID.randomUUID().toString())
      .clientId(clientIdService.incrementClientId(client.clientId))
      .clientIdIssuedAt(java.time.Instant.now())
      .clientSecret(oAuthClientSecret.encode(externalClientSecret))
      .build()

    registeredClientRepository.save(duplicatedRegisteredClient)
    val authorizationConsent = authorizationConsentRepository.findByIdOrNull(AuthorizationConsentId(client.id, client.clientId))
    authorizationConsent?.let {
      authorizationConsentRepository.save(AuthorizationConsent(duplicatedRegisteredClient.id, duplicatedRegisteredClient.clientId, it.authorities))
    }

    return DuplicateRegistrationResponse(
      duplicatedRegisteredClient.clientId,
      externalClientSecret,
      getEncoder().encodeToString(duplicatedRegisteredClient.clientId.toByteArray()),
      getEncoder().encodeToString(externalClientSecret.toByteArray()),
    )
  }
}

data class ClientDetail(
  val baseClientId: String,
  val clientType: ClientType?,
  val teamName: String?,
  val grantType: String,
  val roles: String?,
  val count: Int,
  val expired: String?,
  val lastAccessed: Instant?,
)

class ClientNotFoundException(entityName: String?, clientId: String) : RuntimeException("$entityName for client id $clientId not found")

enum class SortBy {
  CLIENT, TYPE, TEAM, LAST_ACCESSED, COUNT
}

data class ClientFilter(
  val grantType: String? = null,
  val role: String? = null,
  val clientType: ClientType? = null,
)

data class DuplicateRegistrationResponse(
  val clientId: String,
  val clientSecret: String,
  val base64ClientId: String,
  val base64ClientSecret: String,
)
