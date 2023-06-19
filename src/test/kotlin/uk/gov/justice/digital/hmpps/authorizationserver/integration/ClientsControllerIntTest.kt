package uk.gov.justice.digital.hmpps.authorizationserver.integration

import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.web.reactive.function.BodyInserters

class ClientsControllerIntTest : IntegrationTestBase() {

  @Autowired
  lateinit var jdbcRegisteredClientRepository: JdbcRegisteredClientRepository

  @Nested
  inner class AddClient {

    @Test
    fun `access forbidden when no authority`() {
      webTestClient.post().uri("/clients/add")
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy-1",
              "clientName" to "test client",
              "authorizationGrantTypes" to listOf("client_credentials"),
              "scopes" to listOf("read"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.post().uri("/clients/add")
        .headers(setAuthorisation(roles = listOf()))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy-1",
              "clientName" to "test client",
              "authorizationGrantTypes" to listOf("client_credentials"),
              "scopes" to listOf("read"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.post().uri("/clients/add")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy-1",
              "clientName" to "test client",
              "authorizationGrantTypes" to listOf("client_credentials"),
              "scopes" to listOf("read"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `register client success`() {
      assertNull(jdbcRegisteredClientRepository.findByClientId("testy-1"))

      webTestClient.post().uri("/clients/add")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy-1",
              "clientName" to "test client",
              "authorizationGrantTypes" to listOf("client_credentials"),
              "scopes" to listOf("read"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      assertNotNull(jdbcRegisteredClientRepository.findByClientId("testy-1"))
    }
  }
}
