package uk.gov.justice.digital.hmpps.authorizationserver.service

import org.springframework.core.convert.ConversionService
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
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.Hosting
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.AuthorizationConsentRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientDeploymentRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientRepository
import uk.gov.justice.digital.hmpps.authorizationserver.resource.ClientDeploymentDetails
import uk.gov.justice.digital.hmpps.authorizationserver.resource.ClientRegistrationRequest
import uk.gov.justice.digital.hmpps.authorizationserver.resource.ClientRegistrationResponse
import uk.gov.justice.digital.hmpps.authorizationserver.resource.ClientUpdateRequest
import uk.gov.justice.digital.hmpps.authorizationserver.utils.OAuthClientSecret
import java.time.Instant
import java.time.LocalDate
import java.time.temporal.ChronoUnit
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
  private val registeredClientAdditionalInformation: RegisteredClientAdditionalInformation,
  private val conversionService: ConversionService,
) {

  @Transactional(readOnly = true)
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
      val lastAccessed = getMostRecentAccessedDate(client.second) ?: client.second.maxOf { it.clientIdIssuedAt }
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
  fun addClient(clientDetails: ClientRegistrationRequest): ClientRegistrationResponse {
    val clientList = clientIdService.findByBaseClientId(clientDetails.clientId!!)
    if (clientList.isNotEmpty()) {
      throw ClientAlreadyExistsException(clientDetails.clientId)
    }

    var client = conversionService.convert(clientDetails, Client::class.java)
    val externalClientSecret = oAuthClientSecret.generate()
    client!!.clientSecret = oAuthClientSecret.encode(externalClientSecret)

    client = clientRepository.save(client)
    clientDetails.authorities?.let { authorities ->
      authorizationConsentRepository.save(AuthorizationConsent(client!!.id!!, client.clientId, withAuthoritiesPrefix(authorities)))
    }

    clientDetails.ips?.let { ips ->
      clientConfigRepository.save(ClientConfig(client!!.clientId, ips, getClientEndDate(clientDetails.validDays)))
    }

    return ClientRegistrationResponse(
      client!!.clientId,
      externalClientSecret,
      getEncoder().encodeToString(client.clientId.toByteArray()),
      getEncoder().encodeToString(externalClientSecret.toByteArray()),
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

  @Transactional(readOnly = true)
  fun findClientWithCopies(clientId: String): List<Client> {
    val clients = clientIdService.findByBaseClientId(clientId)
    if (clients.isEmpty()) {
      throw ClientNotFoundException(Client::class.simpleName, clientId)
    }
    return clients
  }

  @Transactional(readOnly = true)
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
      .clientIdIssuedAt(Instant.now())
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

  @Transactional
  fun editClient(clientId: String, clientDetails: ClientUpdateRequest) {
    val clientClientConfigPair = retrieveClientWithClientConfig(clientId)
    val clientList = clientClientConfigPair.first
    val clientConfig = clientClientConfigPair.second

    clientList.forEach {
      with(clientDetails) {
        it.scopes = scopes
        it.tokenSettings = registeredClientAdditionalInformation.buildTokenSettings(
          accessTokenValidityMinutes,
          databaseUserName,
          jiraNumber,
        )
        updateClientConfig(clientId, clientConfig, this)
        updateAuthorizationConsent(it, clientDetails)
      }
    }
  }

  @Transactional(readOnly = true)
  fun retrieveClientFullDetails(clientId: String): ClientComposite {
    val clientClientConfigPair = retrieveLatestClientWithClientConfig(clientId)
    val client = clientClientConfigPair.first
    val clientConfig = clientClientConfigPair.second
    val deployment = getDeployment(clientId)
    setValidDays(clientConfig)
    return ClientComposite(client, clientConfig, retrieveAuthorizationConsent(client), deployment)
  }

  @Transactional
  fun upsert(clientId: String, clientDeployment: ClientDeploymentDetails) {
    val baseClientId = clientIdService.toBase(clientId)
    val clientsByBaseClientId = clientIdService.findByBaseClientId(clientId)
    if (clientsByBaseClientId.isEmpty()) {
      throw ClientNotFoundException(Client::class.simpleName, clientId)
    }
    clientDeploymentRepository.save(toClientDeploymentEntity(clientDeployment, baseClientId))
  }

  private fun getMostRecentAccessedDate(clientList: List<Client>) = clientList.map { it.latestClientAuthorization }
    .flatMap { authorizations -> authorizations?.map { it.accessTokenIssuedAt }!!.toCollection(ArrayList()) }.maxOrNull()

  private fun getDeployment(clientId: String): ClientDeploymentDetails? {
    val baseClientId = clientIdService.toBase(clientId)
    val clientDeployment =
      clientDeploymentRepository.findByIdOrNull(baseClientId)
    return clientDeployment?.let { toClientDeploymentDetails(clientDeployment) }
  }

  private fun toClientDeploymentDetails(clientDeployment: ClientDeployment): ClientDeploymentDetails {
    with(clientDeployment) {
      return ClientDeploymentDetails(
        clientType = clientType?.name,
        team = team,
        teamContact = teamContact,
        teamSlack = teamSlack,
        hosting = hosting?.name,
        namespace = namespace,
        deployment = deployment,
        secretName = secretName,
        clientIdKey = clientIdKey,
        secretKey = secretKey,
        deploymentInfo = deploymentInfo,
      )
    }
  }

  private fun toClientDeploymentEntity(clientDeployment: ClientDeploymentDetails, baseClientId: String): ClientDeployment {
    with(clientDeployment) {
      return ClientDeployment(
        baseClientId = baseClientId,
        clientType = clientType?.let { ClientType.valueOf(clientType) },
        team = team,
        teamContact = teamContact,
        teamSlack = teamSlack,
        hosting = hosting?.let { Hosting.valueOf(hosting) },
        namespace = namespace,
        deployment = deployment,
        secretName = secretName,
        clientIdKey = clientIdKey,
        secretKey = secretKey,
        deploymentInfo = deploymentInfo,
      )
    }
  }

  private fun updateAuthorizationConsent(client: Client, clientDetails: ClientUpdateRequest) {
    val authorizationConsent = retrieveAuthorizationConsent(client)
    val authorizationConsentToPersist = authorizationConsent?.let { existingAuthorizationConsent ->
      existingAuthorizationConsent.authorities = withAuthoritiesPrefix(clientDetails.authorities)
      return@let existingAuthorizationConsent
    } ?: AuthorizationConsent(client.id!!, client.clientId, withAuthoritiesPrefix(clientDetails.authorities))

    authorizationConsentRepository.save(authorizationConsentToPersist)
  }

  private fun updateClientConfig(clientId: String, existingClientConfig: ClientConfig?, clientDetails: ClientUpdateRequest) {
    with(clientDetails) {
      val clientConfigToPersist = existingClientConfig?.let { clientConfig ->
        clientConfig.ips = ips
        clientConfig.clientEndDate = getClientEndDate(validDays)
        return@let clientConfig
      } ?: ClientConfig(clientIdService.toBase(clientId), ips, getClientEndDate(validDays))

      clientConfigRepository.save(clientConfigToPersist)
    }
  }

  private fun withAuthoritiesPrefix(authorities: List<String>) =
    authorities
      .map { it.trim().uppercase() }
      .map { if (it.startsWith("ROLE_")) it else "ROLE_$it" }

  private fun retrieveClientWithClientConfig(clientId: String): Pair<List<Client>, ClientConfig?> {
    val existingClients = findClientWithCopies(clientId)
    val existingClientConfig = clientConfigRepository.findByIdOrNull(clientIdService.toBase(clientId))
    return Pair(existingClients, existingClientConfig)
  }

  private fun retrieveLatestClientWithClientConfig(clientId: String): Pair<Client, ClientConfig?> {
    val existingClient = clientRepository.findFirstByClientIdStartingWithOrderByClientIdIssuedAtDesc(clientId) ?: throw ClientNotFoundException(Client::class.simpleName, clientId)
    val existingClientConfig = clientConfigRepository.findByIdOrNull(clientIdService.toBase(clientId))
    return Pair(existingClient, existingClientConfig)
  }

  private fun retrieveAuthorizationConsent(client: Client) =
    authorizationConsentRepository.findByIdOrNull(
      AuthorizationConsentId(
        client.id,
        client.clientId,
      ),
    )

  private fun setValidDays(clientConfig: ClientConfig?) =
    clientConfig?.clientEndDate?.let {
      val daysToClientExpiry = ChronoUnit.DAYS.between(LocalDate.now(), clientConfig.clientEndDate)
      val daysToClientExpiryIncludingToday = daysToClientExpiry + 1
      clientConfig.validDays = if (daysToClientExpiry < 0) 0 else daysToClientExpiryIncludingToday
    }

  private fun getClientEndDate(validDays: Long?): LocalDate? {
    return validDays?.let {
      val validDaysIncludeToday = it.minus(1)
      LocalDate.now().plusDays(validDaysIncludeToday)
    }
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

class ClientAlreadyExistsException(clientId: String) : RuntimeException("Client with client id $clientId cannot be created as already exists")

enum class SortBy {
  CLIENT, TYPE, TEAM, LAST_ACCESSED, COUNT
}

data class ClientFilter(
  val grantType: String? = null,
  val role: String? = null,
  val clientType: ClientType? = null,
)

data class ClientComposite(
  val latestClient: Client,
  val clientConfig: ClientConfig?,
  val authorizationConsent: AuthorizationConsent?,
  val deployment: ClientDeploymentDetails?,
)

data class DuplicateRegistrationResponse(
  val clientId: String,
  val clientSecret: String,
  val base64ClientId: String,
  val base64ClientSecret: String,
)
