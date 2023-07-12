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
import uk.gov.justice.digital.hmpps.authorizationserver.utils.BaseClientId
import uk.gov.justice.digital.hmpps.authorizationserver.utils.OAuthClientSecret
import java.time.Instant
import java.time.LocalDate
import java.util.UUID

@Service
class ClientService(
  private val clientRepository: ClientRepository,
  private val clientConfigRepository: ClientConfigRepository,
  private val authorizationConsentRepository: AuthorizationConsentRepository,
  private val registeredClientAdditionalInformation: RegisteredClientAdditionalInformation,
  private val oAuthClientSecret: OAuthClientSecret,
  private val baseClientId: BaseClientId,
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
    clientConfigRepository.save(ClientConfig(client.clientId, clientDetails.ips, getClientEndDate(clientDetails)))

    return ClientCredentialsRegistrationResponse(client.clientId, externalClientSecret)
  }

  @Transactional
  fun editClientCredentials(clientDetails: ClientCredentialsRegistrationRequest) {
    val existingClient = clientRepository.findClientByClientId(clientDetails.clientId) ?: throw ClientNotFoundException(Client::class.simpleName, clientDetails.clientId)
    val existingClientConfig = clientConfigRepository.findByIdOrNull(baseClientId.toBase(clientDetails.clientId)) ?: throw ClientNotFoundException(ClientConfig::class.simpleName, clientDetails.clientId)

    with(clientDetails) {
      existingClient.clientName = clientName
      existingClient.scopes = scopes
      existingClient.tokenSettings = registeredClientAdditionalInformation.buildTokenSettings(this)
      existingClientConfig.ips = ips
      existingClientConfig.clientEndDate = getClientEndDate(this)
    }
  }

  private fun getClientEndDate(clientDetails: ClientCredentialsRegistrationRequest): LocalDate? {
    return clientDetails.validDays?.let {
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
        tokenSettings = registeredClientAdditionalInformation.buildTokenSettings(this),
      )
    }
  }
}

class ClientAlreadyExistsException(clientId: String) : RuntimeException("Client with client id $clientId cannot be created as already exists")

class ClientNotFoundException(entityName: String?, clientId: String) : RuntimeException("$entityName for client id $clientId not found")
