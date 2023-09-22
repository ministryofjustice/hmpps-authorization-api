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
import uk.gov.justice.digital.hmpps.authorizationserver.utils.OAuthClientSecret
import java.time.LocalDate
import java.time.temporal.ChronoUnit
import java.util.Base64.getEncoder

@Service
class ClientCredentialsService(
  private val clientRepository: ClientRepository,
  private val clientConfigRepository: ClientConfigRepository,
  private val authorizationConsentRepository: AuthorizationConsentRepository,
  private val registeredClientAdditionalInformation: RegisteredClientAdditionalInformation,
  private val oAuthClientSecret: OAuthClientSecret,
  private val clientIdService: ClientIdService,
  private val conversionService: ConversionService,

) {

  @Transactional
  fun addClientCredentials(clientDetails: ClientCredentialsRegistrationRequest): ClientCredentialsRegistrationResponse {
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

    return ClientCredentialsRegistrationResponse(
      client!!.clientId,
      externalClientSecret,
      getEncoder().encodeToString(client!!.clientId.toByteArray()),
      getEncoder().encodeToString(externalClientSecret.toByteArray()),
    )
  }

  @Transactional
  fun editClientCredentials(clientId: String, clientDetails: ClientCredentialsUpdateRequest) {
    val clientClientConfigPair = retrieveClientWithClientConfig(clientId)
    val client = clientClientConfigPair.first
    val clientConfig = clientClientConfigPair.second

    with(clientDetails) {
      client.scopes = scopes
      client.tokenSettings = registeredClientAdditionalInformation.buildTokenSettings(accessTokenValidityMinutes, databaseUserName, jiraNumber)
      updateClientConfig(clientId, clientConfig, this)
      updateAuthorizationConsent(client, clientDetails)
    }
  }

  @Transactional(readOnly = true)
  fun retrieveClientFullDetails(clientId: String): ClientComposite {
    val clientClientConfigPair = retrieveClientWithClientConfig(clientId)
    val client = clientClientConfigPair.first
    val clientConfig = clientClientConfigPair.second
    setValidDays(clientConfig)
    return ClientComposite(client, clientConfig, retrieveAuthorizationConsent(client))
  }

  private fun updateAuthorizationConsent(client: Client, clientDetails: ClientCredentialsUpdateRequest) {
    val authorizationConsent = retrieveAuthorizationConsent(client)
    val authorizationConsentToPersist = authorizationConsent?.let { existingAuthorizationConsent ->
      existingAuthorizationConsent.authorities = withAuthoritiesPrefix(clientDetails.authorities)
      return@let existingAuthorizationConsent
    } ?: AuthorizationConsent(client.id!!, client.clientId, withAuthoritiesPrefix(clientDetails.authorities))

    authorizationConsentRepository.save(authorizationConsentToPersist)
  }

  private fun updateClientConfig(clientId: String, existingClientConfig: ClientConfig?, clientDetails: ClientCredentialsUpdateRequest) {
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

  private fun retrieveClientWithClientConfig(clientId: String): Pair<Client, ClientConfig?> {
    val existingClient = clientRepository.findClientByClientId(clientId) ?: throw ClientNotFoundException(Client::class.simpleName, clientId)
    val existingClientConfig = clientConfigRepository.findByIdOrNull(clientIdService.toBase(clientId))
    return Pair(existingClient, existingClientConfig)
  }

  private fun retrieveAuthorizationConsent(client: Client) =
    authorizationConsentRepository.findByIdOrNull(
      AuthorizationConsent.AuthorizationConsentId(
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

data class ClientComposite(
  val latestClient: Client,
  val clientConfig: ClientConfig?,
  val authorizationConsent: AuthorizationConsent?,
)

class ClientAlreadyExistsException(clientId: String) : RuntimeException("Client with client id $clientId cannot be created as already exists")
