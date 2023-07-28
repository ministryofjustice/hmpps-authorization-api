package uk.gov.justice.digital.hmpps.authorizationserver.service

import org.springframework.core.convert.ConversionService
import org.springframework.data.repository.findByIdOrNull
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
import java.time.LocalDate
import java.time.temporal.ChronoUnit

@Service
class ClientCredentialsService(
  private val clientRepository: ClientRepository,
  private val clientConfigRepository: ClientConfigRepository,
  private val authorizationConsentRepository: AuthorizationConsentRepository,
  private val registeredClientAdditionalInformation: RegisteredClientAdditionalInformation,
  private val oAuthClientSecret: OAuthClientSecret,
  private val clientIdConverter: ClientIdConverter,
  private val conversionService: ConversionService,
) {

  @Transactional
  fun addClientCredentials(clientDetails: ClientCredentialsRegistrationRequest): ClientCredentialsRegistrationResponse {
    val existingClient = clientRepository.findClientByClientId(clientDetails.clientId)
    existingClient?.let {
      throw ClientAlreadyExistsException(clientDetails.clientId)
    }

    var client = conversionService.convert(clientDetails, Client::class.java)
    val externalClientSecret = oAuthClientSecret.generate()
    client!!.clientSecret = oAuthClientSecret.encode(externalClientSecret)

    client = clientRepository.save(client)
    authorizationConsentRepository.save(AuthorizationConsent(client!!.id!!, client.clientId, clientDetails.authorities))
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
  fun retrieveClientFullDetails(clientId: String): ClientComposite {
    val clientClientConfigPair = retrieveClientWithClientConfig(clientId)
    val client = clientClientConfigPair.first
    val clientConfig = clientClientConfigPair.second
    setValidDays(clientConfig)
    return ClientComposite(listOf(client), client, clientConfig, retrieveAuthorizationConsent(client))
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
}

data class ClientComposite(
  val clients: List<Client>,
  val latestClient: Client,
  val clientConfig: ClientConfig,
  val authorizationConsent: AuthorizationConsent,
)

class ClientAlreadyExistsException(clientId: String) : RuntimeException("Client with client id $clientId cannot be created as already exists")

class ClientNotFoundException(entityName: String?, clientId: String) : RuntimeException("$entityName for client id $clientId not found")
