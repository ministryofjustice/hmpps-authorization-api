package uk.gov.justice.digital.hmpps.authorizationapi.integration

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.mockito.kotlin.whenever
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.test.context.TestPropertySource
import org.springframework.test.context.bean.override.mockito.MockitoBean
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.reactive.function.BodyInserters
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.AuthorizationConsent
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.Client
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.AuthorizationConsentRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientRepository
import uk.gov.justice.digital.hmpps.authorizationapi.utils.OAuthClientSecret
import java.time.Duration
import java.util.Base64.getEncoder
import kotlin.streams.asSequence

/**
 * Test verifies that [Client.tokenSettings].authorizationCodeTimeToLive config can be overridden in
 * application properties
 */
@Transactional
@TestPropertySource(
  properties = [
    "application.oauth2.authorizationcode.timetolive=PT13M",
  ],
)
class TokenSettingsAuthorizationCodeTimeToLiveConfigTest : IntegrationTestBase() {

  @Autowired
  lateinit var clientRepository: ClientRepository

  @Autowired
  lateinit var clientConfigRepository: ClientConfigRepository

  @Autowired
  lateinit var authorizationConsentRepository: AuthorizationConsentRepository

  @MockitoBean
  lateinit var oAuthClientSecretGenerator: OAuthClientSecret

  companion object {
    private const val CLIENT_ID_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private val CLIENT_ID = "test-client-${randomString()}"

    private fun randomString(): String = java.util.Random()
      .ints(10, 0, CLIENT_ID_CHARSET.length)
      .asSequence()
      .map(CLIENT_ID_CHARSET::get)
      .joinToString("")
  }

  @AfterEach
  fun tearDown() {
    clientRepository.findClientByClientId(CLIENT_ID)?.let {
      clientRepository.deleteByClientId(it.clientId)

      clientConfigRepository.deleteByBaseClientId(it.clientId)

      authorizationConsentRepository.deleteById(
        AuthorizationConsent.AuthorizationConsentId(it.id, it.clientName),
      )
    }
    assertThat(clientRepository.findClientByClientId(CLIENT_ID)).isNull()
  }

  /**
   * Test overrides the default [Client.tokenSettings#authorizationCodeTimeToLive] configuration, creates a new client
   * and verifies the client.tokensettings contain the expected auth code ttl value.
   **/
  @Test
  fun `create client sets expected tokenSettings authorizationCodeTimeToLive when override is provided in application properties`() {
    assertNull(clientRepository.findClientByClientId(CLIENT_ID))

    whenever(oAuthClientSecretGenerator.generate())
      .thenReturn("external-client-secret")

    whenever(oAuthClientSecretGenerator.encode("external-client-secret"))
      .thenReturn("encoded-client-secret")

    webTestClient.post().uri("/base-clients")
      .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
      .body(
        BodyInserters.fromValue(
          mapOf(
            "clientId" to CLIENT_ID,
            "grantType" to "authorization_code",
            "scopes" to listOf("read", "write"),
            "authorities" to emptyList<String>(),
            "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
            "databaseUserName" to "testy-mctest",
            "jiraNumber" to "HAAR-9999",
            "validDays" to 5,
            "accessTokenValiditySeconds" to 20,
            "skipToAzure" to true,
            "resourceIds" to emptyList<String>(),
          ),
        ),
      )
      .exchange()
      .expectStatus().isOk
      .expectBody()
      .jsonPath("clientId").isEqualTo(CLIENT_ID)
      .jsonPath("clientSecret").isEqualTo("external-client-secret")
      .jsonPath("base64ClientId").isEqualTo(getEncoder().encodeToString(CLIENT_ID.toByteArray()))
      .jsonPath("base64ClientSecret").isEqualTo(getEncoder().encodeToString("external-client-secret".toByteArray()))

    val client: Client? = clientRepository.findClientByClientId(CLIENT_ID)

    assertNotNull(client)
    assertThat(client!!.tokenSettings).isNotNull
    assertThat(client.tokenSettings.authorizationCodeTimeToLive).isEqualTo(Duration.ofMinutes(13))
  }
}
