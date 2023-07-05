package uk.gov.justice.digital.hmpps.authorizationserver.service

import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
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
    clientConfigRepository.save(ClientConfig(client.clientId, clientDetails.ips, determineClientEndDate(clientDetails)))

    return ClientCredentialsRegistrationResponse(client.clientId, externalClientSecret)
  }

  private fun determineClientEndDate(clientDetails: ClientCredentialsRegistrationRequest): LocalDate? {
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
        tokenSettings =
        TokenSettings.builder()
          .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
          .build(),
        additionalInformation = registeredClientAdditionalInformation.mapFrom(this),
      )
    }
  }
}

class ClientAlreadyExistsException(clientId: String) : RuntimeException("Client with client id $clientId cannot be created as already exists")
