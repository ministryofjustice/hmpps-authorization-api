package uk.gov.justice.digital.hmpps.authorizationapi.data.model

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import java.time.LocalDateTime

class ClientTest {

  @Test
  fun shouldUseMostRecentAccessTokenIssuedAtDateTime() {
    val yesterday = LocalDateTime.now().minusDays(1)
    val authorizationOAuth2s = mutableSetOf(
      givenAuthorizationOAuth2With("client_credentials", LocalDateTime.now().minusDays(3), null),
      givenAuthorizationOAuth2With("client_credentials", LocalDateTime.now().minusDays(2), null),
      givenAuthorizationOAuth2With("client_credentials", yesterday, null),
    )

    val clientOAuth2 = givenClientOAuth2With(
      latestClientAuthorization = authorizationOAuth2s,
      migratedLastAccessed = LocalDateTime.now().minusDays(10),
      clientIdIssuedAt = LocalDateTime.now().minusDays(20),
    )

    assertThat(clientOAuth2.getLastAccessedDate()).isEqualTo(yesterday)
  }

  @Test
  fun shouldUseMostRecentAuthorisationCodeIssuedAtDateTime() {
    val yesterday = LocalDateTime.now().minusDays(1)
    val authorizationOAuth2s = mutableSetOf(
      givenAuthorizationOAuth2With("authorization_code", null, LocalDateTime.now().minusDays(3)),
      givenAuthorizationOAuth2With("authorization_code", null, LocalDateTime.now().minusDays(2)),
      givenAuthorizationOAuth2With("authorization_code", null, yesterday),
    )

    val clientOAuth2 = givenClientOAuth2With(
      latestClientAuthorization = authorizationOAuth2s,
      migratedLastAccessed = LocalDateTime.now().minusDays(10),
      clientIdIssuedAt = LocalDateTime.now().minusDays(20),
    )

    assertThat(clientOAuth2.getLastAccessedDate()).isEqualTo(yesterday)
  }

  @Test
  fun shouldUseMigratedLastAccessedDateWhenNoTokensIssued() {
    val tenDaysAgo = LocalDateTime.now().minusDays(10)

    val clientOAuth2 = givenClientOAuth2With(
      latestClientAuthorization = null,
      migratedLastAccessed = tenDaysAgo,
      clientIdIssuedAt = LocalDateTime.now().minusDays(20),
    )

    assertThat(clientOAuth2.getLastAccessedDate()).isEqualTo(tenDaysAgo)
  }

  @Test
  fun shouldUseClientIdIssuedAtDateTimeWhenNoTokensIssuedAndMigratedLastAccessedNotPresent() {
    val tenDaysAgo = LocalDateTime.now().minusDays(10)

    val clientOAuth2 = givenClientOAuth2With(
      latestClientAuthorization = null,
      migratedLastAccessed = null,
      clientIdIssuedAt = tenDaysAgo,
    )

    assertThat(clientOAuth2.getLastAccessedDate()).isEqualTo(tenDaysAgo)
  }

  private fun givenClientOAuth2With(
    latestClientAuthorization: MutableSet<Authorization>?,
    migratedLastAccessed: LocalDateTime?,
    clientIdIssuedAt: LocalDateTime,
  ): Client = Client(
    id = "1234",
    clientId = "clientId",
    clientIdIssuedAt = clientIdIssuedAt,
    clientSecret = "clientSecret",
    clientSecretExpiresAt = LocalDateTime.now(),
    clientName = "clientName",
    clientAuthenticationMethods = "clientAuthenticationMethods",
    authorizationGrantTypes = "authorizationGrantTypes",
    redirectUris = "redirectUris",
    postLogoutRedirectUris = null,
    scopes = emptyList(),
    clientSettings = ClientSettings.withSettings(mutableMapOf("clientId" to "clientId", "clientSecret" to "clientSecret") as Map<String, Any>?).build(),
    tokenSettings = TokenSettings.withSettings(mutableMapOf("clientId" to "clientId", "clientSecret" to "clientSecret") as Map<String, Any>?).build(),
    migratedLastAccessed = migratedLastAccessed,
    latestClientAuthorization = latestClientAuthorization,
    mfaRememberMe = false,
    mfa = null,
    skipToAzure = false,
    resourceIds = emptyList(),
  )

  private fun givenAuthorizationOAuth2With(
    authorizationGrantType: String,
    accessTokenIssuedAt: LocalDateTime?,
    authorizationCodeIssuedAt: LocalDateTime?,
  ): Authorization = Authorization(
    id = "1234",
    registeredClientId = "clientId",
    principalName = "testy",
    authorizationGrantType = authorizationGrantType,
    authorizedScopes = null,
    attributes = null,
    state = null,
    authorizationCodeValue = null,
    authorizationCodeIssuedAt = authorizationCodeIssuedAt,
    authorizationCodeExpiresAt = null,

    authorizationCodeMetadata = null,
    accessTokenValue = "1234",
    accessTokenIssuedAt = accessTokenIssuedAt,
    accessTokenExpiresAt = null,
    accessTokenMetadata = null,
    accessTokenType = null,
    accessTokenScopes = null,
  )
}
