package uk.gov.justice.digital.hmpps.authorizationserver.integration

import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpHeaders
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.web.reactive.function.BodyInserters
import java.util.Base64

class OidcIntTest : IntegrationTestBase() {

  @Autowired
  lateinit var jdbcRegisteredClientRepository: JdbcRegisteredClientRepository

  @Nested
  inner class Registration {

    @Test
    fun `should register client using given client id`() {
      val clientCredentialsResponse = webTestClient
        .post().uri("/oauth2/token?grant_type=client_credentials")
        .header(
          HttpHeaders.AUTHORIZATION,
          "Basic " + Base64.getEncoder().encodeToString(("test-client-create-id:test-secret").toByteArray()),
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .returnResult().responseBody

      val accessToken = JSONObject(String(clientCredentialsResponse)).get("access_token")

      webTestClient
        .post().uri("/connect/register")
        .header(HttpHeaders.AUTHORIZATION, "Bearer $accessToken")
        .body(
          BodyInserters.fromValue(
            mapOf(
              "client_id" to "authorization_code_register_test",
              "client_name" to "authorization_code_registration_test",
              "access_token_validity" to "1200",
              "scope" to "read write",
              "authorities" to "MAINTAIN_OAUTH_USERS,AUTH_GROUP_MANAGER",
              "token_endpoint_auth_method" to "client_secret_basic",
              "jwks_uri" to "https://client.example.org/my_public_keys.jwks",
              "grant_types" to "authorization_code",
              "redirect_uris" to "http://localhost:3000",
              "databaseUsername" to "fred",
              "response_types" to "id_token",
            ),
          ),
        )
        .exchange()
        .expectStatus().isCreated

      assertNotNull(jdbcRegisteredClientRepository.findByClientId("authorization_code_register_test"))
    }
  }
}