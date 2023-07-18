package uk.gov.justice.digital.hmpps.authorizationserver.service.converter

import org.springframework.core.convert.converter.Converter
import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.Client
import uk.gov.justice.digital.hmpps.authorizationserver.resource.ClientCredentialsRegistrationRequest
import uk.gov.justice.digital.hmpps.authorizationserver.service.RegisteredClientAdditionalInformation

@Component
class ClientConverter(
  private val registeredClientAdditionalInformation: RegisteredClientAdditionalInformation,
) : Converter<ClientCredentialsRegistrationRequest, Client> {
  override fun convert(source: ClientCredentialsRegistrationRequest): Client? {
    with(source) {
      return Client(
        id = java.util.UUID.randomUUID().toString(),
        clientId = clientId,
        clientIdIssuedAt = java.time.Instant.now(),
        clientSecretExpiresAt = null,
        clientName = clientName,
        clientAuthenticationMethods = org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC.value,
        authorizationGrantTypes = org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS.value,
        scopes = scopes,
        clientSettings =
        org.springframework.security.oauth2.server.authorization.settings.ClientSettings.builder()
          .requireProofKey(false)
          .requireAuthorizationConsent(false).build(),
        tokenSettings = registeredClientAdditionalInformation.buildTokenSettings(accessTokenValidity, databaseUserName, jiraNumber),
      )
    }
  }
}
