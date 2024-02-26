package uk.gov.justice.digital.hmpps.authorizationserver.service.converter

import org.springframework.core.convert.converter.Converter
import org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC
import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.Client
import uk.gov.justice.digital.hmpps.authorizationserver.resource.MigrationClientRequest
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientIdService
import uk.gov.justice.digital.hmpps.authorizationserver.service.RegisteredClientAdditionalInformation
import java.time.ZoneOffset

@Component
class MigrationClientConverter(
  private val registeredClientAdditionalInformation: RegisteredClientAdditionalInformation,
  private val clientIdService: ClientIdService,
) : Converter<MigrationClientRequest, Client> {
  override fun convert(source: MigrationClientRequest): Client {
    with(source) {
      return Client(
        id = java.util.UUID.randomUUID().toString(),
        clientId = clientId,
        clientIdIssuedAt = lastAccessed ?: clientIdIssuedAt,
        clientSecretExpiresAt = clientEndDate?.atStartOfDay()?.toInstant(ZoneOffset.UTC),
        clientName = clientIdService.toBase(clientId),
        clientAuthenticationMethods = CLIENT_SECRET_BASIC.value,
        authorizationGrantTypes = grantType,
        scopes = scopes ?: listOf("read"),
        clientSettings =
        org.springframework.security.oauth2.server.authorization.settings.ClientSettings.builder()
          .requireProofKey(false)
          .requireAuthorizationConsent(false).build(),
        tokenSettings = registeredClientAdditionalInformation.buildTokenSettings(
          accessTokenValiditySeconds,
        ),
        databaseUsername = databaseUserName,
        jira = jiraNumber,
        latestClientAuthorization = mutableSetOf(),
        clientSecret = if (clientSecret.startsWith("{bcrypt}")) {
          clientSecret
        } else {
          "{bcrypt}$clientSecret"
        },
        jwtFields = jwtFields,
        mfa = mfa,
        mfaRememberMe = mfaRememberMe,
        redirectUris = redirectUris,
      )
    }
  }
}
