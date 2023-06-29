package uk.gov.justice.digital.hmpps.authorizationserver.integration

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.web.reactive.function.BodyInserters
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.AuthorizationConsent
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.AuthorizationConsentRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientConfigRepository

class ClientsControllerIntTest : IntegrationTestBase() {

  @Autowired
  lateinit var jdbcRegisteredClientRepository: JdbcRegisteredClientRepository

  @Autowired
  lateinit var clientConfigRepository: ClientConfigRepository

  @Autowired
  lateinit var authorizationConsentRepository: AuthorizationConsentRepository

  @Nested
  inner class AddClient {

    @Test
    fun `access forbidden when no authority`() {
      webTestClient.post().uri("/clients/client-credentials/add")
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
              "clientName" to "test client",
              "scopes" to listOf("read"),
              "authorities" to listOf("VIEW_PRISONER_DATA"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.post().uri("/clients/client-credentials/add")
        .headers(setAuthorisation(roles = listOf()))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
              "clientName" to "test client",
              "scopes" to listOf("read"),
              "authorities" to listOf("VIEW_PRISONER_DATA"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.post().uri("/clients/client-credentials/add")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
              "clientName" to "test client",
              "scopes" to listOf("read"),
              "authorities" to listOf("VIEW_PRISONER_DATA"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `bad request when client already exists`() {
      assertNotNull(jdbcRegisteredClientRepository.findByClientId("test-client-id"))

      webTestClient.post().uri("/clients/client-credentials/add")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "test-client-id",
              "clientName" to "test client",
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isBadRequest
        .expectBody()
        .json(
          """
              {
              "userMessage":"Client with client id test-client-id cannot be created as already exists",
              "developerMessage":"Client with client id test-client-id cannot be created as already exists"
              }
          """
            .trimIndent(),
        )
    }

    @Test
    fun `register client success`() {
      assertNull(jdbcRegisteredClientRepository.findByClientId("testy-1"))

      webTestClient.post().uri("/clients/client-credentials/add")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
              "clientName" to "test client",
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      val registeredClient = jdbcRegisteredClientRepository.findByClientId("testy")

      assertNotNull(registeredClient)
      assertThat(registeredClient!!.clientId).isEqualTo("testy")
      assertThat(registeredClient.clientName).isEqualTo("test client")
      assertThat(registeredClient.authorizationGrantTypes).contains(AuthorizationGrantType.CLIENT_CREDENTIALS)
      assertThat(registeredClient.scopes).contains("read", "write")

      val clientConfig = clientConfigRepository.findById(registeredClient.clientId).get()
      assertThat(clientConfig.ips).contains("81.134.202.29/32", "35.176.93.186/32")

      val authorizationConsent = authorizationConsentRepository.findById(
        AuthorizationConsent.AuthorizationConsentId(
          registeredClient.id,
          registeredClient.clientId,
        ),
      ).get()
      assertThat(authorizationConsent.authorities).contains("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY")
    }
  }
}
