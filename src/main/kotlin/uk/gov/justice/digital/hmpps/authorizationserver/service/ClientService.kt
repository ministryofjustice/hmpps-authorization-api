package uk.gov.justice.digital.hmpps.authorizationserver.service

import org.springframework.data.repository.findByIdOrNull
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.AuthorizationConsent
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.Client
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientConfig
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.AuthorizationConsentRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientRepository
import uk.gov.justice.digital.hmpps.authorizationserver.resource.ClientCredentialsRegistrationRequest
import uk.gov.justice.digital.hmpps.authorizationserver.resource.ClientCredentialsRegistrationResponse
import uk.gov.justice.digital.hmpps.authorizationserver.resource.ClientCredentialsUpdateRequest
import uk.gov.justice.digital.hmpps.authorizationserver.utils.ClientIdConverter
import uk.gov.justice.digital.hmpps.authorizationserver.utils.OAuthClientSecret
import java.time.Instant
import java.time.LocalDate
import java.time.temporal.ChronoUnit
import java.util.UUID

@Service
class ClientService(
  private val clientRepository: ClientRepository,
  private val clientConfigRepository: ClientConfigRepository,
  private val authorizationConsentRepository: AuthorizationConsentRepository,
  private val registeredClientAdditionalInformation: RegisteredClientAdditionalInformation,
  private val oAuthClientSecret: OAuthClientSecret,
  private val clientIdConverter: ClientIdConverter,
) {

  @Transactional
  fun addClientCredentials(clientDetails: ClientCredentialsRegistrationRequest): ClientCredentialsRegistrationResponse {
    val existingClient = clientRepository.findClientByClientId(clientDetails.clientId)
    existingClient?.let {
      throw ClientAlreadyExistsException(clientDetails.clientId)
    }

    val externalClientSecret = oAuthClientSecret.generate()
    val client = clientRepository.save(buildNewClient(clientDetails, oAuthClientSecret.encode(externalClientSecret)))
    authorizationConsentRepository.save(AuthorizationConsent(client.id!!, client.clientId, clientDetails.authorities))
    clientConfigRepository.save(ClientConfig(client.clientId, clientDetails.ips, getClientEndDate(clientDetails.validDays)))

    return ClientCredentialsRegistrationResponse(client.clientId, externalClientSecret)
  }

  @Transactional
  fun editClientCredentials(clientId: String, clientDetails: ClientCredentialsUpdateRequest) {
    val clientClientConfigPair = retrieveClientWithClientConfig(clientId)
    val client = clientClientConfigPair.first
    val clientConfig = clientClientConfigPair.second

    val authorizationConsent = retrieveAuthorizationConsent(client)

    with(clientDetails) {
      client.scopes = scopes
      client.tokenSettings = registeredClientAdditionalInformation.buildTokenSettings(accessTokenValidity, databaseUserName, jiraNumber)
      clientConfig.ips = ips
      clientConfig.clientEndDate = getClientEndDate(validDays)
      authorizationConsent.authorities = authorities
    }
  }

  @Transactional(readOnly = true)
  fun retrieveAllClientDetails(clientId: String): AllClientDetails {
    val clientClientConfigPair = retrieveClientWithClientConfig(clientId)
    val client = clientClientConfigPair.first
    val clientConfig = clientClientConfigPair.second
    setValidDays(clientConfig)
    return AllClientDetails(listOf(client), client, clientConfig, retrieveAuthorizationConsent(client))
  }

  private fun retrieveClientWithClientConfig(clientId: String): Pair<Client, ClientConfig> {
    val existingClient = clientRepository.findClientByClientId(clientId) ?: throw ClientNotFoundException(Client::class.simpleName, clientId)
    val existingClientConfig = clientConfigRepository.findByIdOrNull(clientIdConverter.toBase(clientId)) ?: throw ClientNotFoundException(ClientConfig::class.simpleName, clientId)
    return Pair(existingClient, existingClientConfig)
  }

  private fun retrieveAuthorizationConsent(client: Client) =
    authorizationConsentRepository.findByIdOrNull(
      AuthorizationConsent.AuthorizationConsentId(
        client.id,
        client.clientId,
      ),
    )
      ?: throw ClientNotFoundException(AuthorizationConsent::class.simpleName, client.clientId)

  private fun setValidDays(clientConfig: ClientConfig) =
    clientConfig.clientEndDate?.let {
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

  private fun buildNewClient(clientDetails: ClientCredentialsRegistrationRequest, encodedClientSecret: String): Client {
    with(clientDetails) {
      return Client(
        id = UUID.randomUUID().toString(),
        clientId = clientId,
        clientIdIssuedAt = Instant.now(),
        clientSecret = encodedClientSecret,
        clientSecretExpiresAt = null,
        clientName = clientName,
        clientAuthenticationMethods = ClientAuthenticationMethod.CLIENT_SECRET_BASIC.value,
        authorizationGrantTypes = AuthorizationGrantType.CLIENT_CREDENTIALS.value,
        scopes = scopes,
        clientSettings =
        ClientSettings.builder()
          .requireProofKey(false)
          .requireAuthorizationConsent(false).build(),
        tokenSettings = registeredClientAdditionalInformation.buildTokenSettings(accessTokenValidity, databaseUserName, jiraNumber),
      )
    }
  }
}

data class AllClientDetails(
  val clients: List<Client>,
  val latestClient: Client,
  val clientConfig: ClientConfig,
  val authorizationConsent: AuthorizationConsent,
)

class ClientAlreadyExistsException(clientId: String) : RuntimeException("Client with client id $clientId cannot be created as already exists")

class ClientNotFoundException(entityName: String?, clientId: String) : RuntimeException("$entityName for client id $clientId not found")
