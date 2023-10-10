package uk.gov.justice.digital.hmpps.authorizationserver.integration

import com.microsoft.applicationinsights.TelemetryClient
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.mockito.kotlin.whenever
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.data.repository.findByIdOrNull
import org.springframework.web.reactive.function.BodyInserters
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.AuthorizationConsent
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.AuthorizationConsentRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientRepository
import uk.gov.justice.digital.hmpps.authorizationserver.utils.OAuthClientSecret

class ClientCredentialsControllerIntTest : IntegrationTestBase() {

  @Autowired
  lateinit var clientConfigRepository: ClientConfigRepository

  @Autowired
  lateinit var authorizationConsentRepository: AuthorizationConsentRepository

  @Autowired
  lateinit var clientRepository: ClientRepository

  @MockBean
  lateinit var oAuthClientSecretGenerator: OAuthClientSecret

  @MockBean
  private lateinit var telemetryClient: TelemetryClient

  @Nested
  inner class ViewClient {

    @Test
    fun `access forbidden when no authority`() {
      webTestClient.get().uri("/base-clients/testy")
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.get().uri("/base-clients/testy")
        .headers(setAuthorisation(roles = listOf()))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.get().uri("/base-clients/testy")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `not found`() {
      webTestClient.get().uri("/base-clients/not-found")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isNotFound
    }

    @Test
    fun `view client success`() {
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "test-more-test",
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testy-more-mctest-1",
              "jiraNumber" to "HAAR-7777",
              "validDays" to 5,
              "accessTokenValidityMinutes" to 20,
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      webTestClient.get().uri("/base-clients/test-more-test")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("clientId").isEqualTo("test-more-test")
        .jsonPath("scopes[0]").isEqualTo("read")
        .jsonPath("scopes[1]").isEqualTo("write")
        .jsonPath("authorities[0]").isEqualTo("ROLE_CURIOUS_API")
        .jsonPath("authorities[1]").isEqualTo("ROLE_VIEW_PRISONER_DATA")
        .jsonPath("authorities[2]").isEqualTo("ROLE_COMMUNITY")
        .jsonPath("ips[0]").isEqualTo("81.134.202.29/32")
        .jsonPath("ips[1]").isEqualTo("35.176.93.186/32")
        .jsonPath("jiraNumber").isEqualTo("HAAR-7777")
        .jsonPath("validDays").isEqualTo(5)
        .jsonPath("accessTokenValidityMinutes").isEqualTo(20)

      val client = clientRepository.findClientByClientId("test-more-test")
      val clientConfig = clientConfigRepository.findById(client!!.clientId).get()
      val authorizationConsent = authorizationConsentRepository.findById(AuthorizationConsent.AuthorizationConsentId(client.id, client.clientId)).get()
      clientRepository.delete(client)
      clientConfigRepository.delete(clientConfig)
      authorizationConsentRepository.delete(authorizationConsent)
    }

    @Test
    fun `view incomplete client success`() {
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "test-more-test",
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      webTestClient.get().uri("/base-clients/test-more-test")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("clientId").isEqualTo("test-more-test")
        .jsonPath("scopes[0]").isEqualTo("read")

      val client = clientRepository.findClientByClientId("test-more-test")
      assertNull(clientConfigRepository.findByIdOrNull(client!!.clientId))
      assertNull(authorizationConsentRepository.findByIdOrNull(AuthorizationConsent.AuthorizationConsentId(client.id, client.clientId)))
      clientRepository.delete(client)
    }
  }

  private fun verifyAuthorities(id: String, clientId: String, vararg authorities: String): AuthorizationConsent {
    val authorizationConsent = authorizationConsentRepository.findById(AuthorizationConsent.AuthorizationConsentId(id, clientId)).get()
    assertThat(authorizationConsent.authorities).containsOnly(*authorities)
    return authorizationConsent
  }
}
