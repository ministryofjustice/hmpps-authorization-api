package uk.gov.justice.digital.hmpps.authorizationapi.service.converter

import org.springframework.core.convert.converter.Converter
import org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC
import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.Client
import uk.gov.justice.digital.hmpps.authorizationapi.resource.ClientRegistrationRequest
import uk.gov.justice.digital.hmpps.authorizationapi.service.ClientIdService
import uk.gov.justice.digital.hmpps.authorizationapi.service.RegisteredClientAdditionalInformation

@Component
class ClientConverter(
  private val registeredClientAdditionalInformation: RegisteredClientAdditionalInformation,
  private val clientIdService: ClientIdService,
) : Converter<ClientRegistrationRequest, Client> {
  override fun convert(source: ClientRegistrationRequest): Client {
    with(source) {
      return Client(
        id = java.util.UUID.randomUUID().toString(),
        clientId = clientId!!,
        clientIdIssuedAt = java.time.Instant.now(),
        clientSecretExpiresAt = null,
        clientName = clientIdService.toBase(clientId),
        clientAuthenticationMethods = CLIENT_SECRET_BASIC.value,
        authorizationGrantTypes = grantType.name,
        scopes = scopes ?: listOf("read"),
        clientSettings = registeredClientAdditionalInformation.buildClientSettings(databaseUserName, jiraNumber),
        tokenSettings = registeredClientAdditionalInformation.buildTokenSettings(accessTokenValiditySeconds),
        latestClientAuthorization = mutableSetOf(),
        jwtFields = jwtFields,
        mfa = mfa,
        mfaRememberMe = mfaRememberMe,
        redirectUris = redirectUris,
        skipToAzureField = skipToAzureField,
        resourceIds = if (source.resourceIds == null) emptyList() else resourceIds,
      )
    }
  }
}
