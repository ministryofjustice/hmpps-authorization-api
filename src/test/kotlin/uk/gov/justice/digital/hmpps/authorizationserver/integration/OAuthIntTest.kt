package uk.gov.justice.digital.hmpps.authorizationserver.integration

import com.microsoft.applicationinsights.TelemetryClient
import org.assertj.core.api.Assertions.assertThat
import org.json.JSONArray
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.mockito.kotlin.verify
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.http.HttpHeaders
import java.util.Base64

class OAuthIntTest : IntegrationTestBase() {

  @MockBean
  private lateinit var telemetryClient: TelemetryClient

  @Nested
  inner class ClientCredentials {

    @Test
    fun `client with database username`() {
      val clientCredentialsResponse = webTestClient
        .post().uri("/oauth2/token?grant_type=client_credentials")
        .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("test-client-id:test-secret").toByteArray()))
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("$").value<Map<String, Any>> {
          assertThat(it["expires_in"] as Int).isLessThan(301)
        }
        .returnResult().responseBody

      val token = getTokenPayload(String(clientCredentialsResponse!!))
      assertThat(token.get("sub")).isEqualTo("test-client-id")
      assertThat(token.get("aud")).isEqualTo("oauth2-resource")
      assertThat(token.get("auth_source")).isEqualTo("none")
      assertThat(token.get("grant_type")).isEqualTo("client_credentials")
      assertThat(token.get("authorities")).isEqualTo(JSONArray(listOf("ROLE_AUDIT", "ROLE_OAUTH_ADMIN", "ROLE_TESTING")))

      assertThat(token.get("database_username")).isEqualTo("testy-db")
      assertTrue(token.isNull("user_name"))
    }

    @Test
    fun `client without database username`() {
      val clientCredentialsResponse = webTestClient
        .post().uri("/oauth2/token?grant_type=client_credentials")
        .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("ip-allow-a-client-1:test-secret").toByteArray()))
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("$").value<Map<String, Any>> {
          assertThat(it["expires_in"] as Int).isLessThan(301)
        }
        .returnResult().responseBody

      val token = getTokenPayload(String(clientCredentialsResponse!!))
      assertThat(token.get("sub")).isEqualTo("ip-allow-a-client-1")
      assertThat(token.get("aud")).isEqualTo("oauth2-resource")
      assertThat(token.get("auth_source")).isEqualTo("none")
      assertThat(token.get("grant_type")).isEqualTo("client_credentials")

      assertTrue(token.isNull("database_username"))
      assertTrue(token.isNull("user_name"))
    }

    @Test
    fun `user name passed in`() {
      val clientCredentialsResponse = webTestClient
        .post().uri("/oauth2/token?grant_type=client_credentials&username=testy")
        .header(
          HttpHeaders.AUTHORIZATION,
          "Basic " + Base64.getEncoder().encodeToString(("test-client-id:test-secret").toByteArray()),
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .returnResult().responseBody

      val token = getTokenPayload(String(clientCredentialsResponse!!))
      assertThat(token.get("sub")).isEqualTo("testy")
      assertThat(token.get("aud")).isEqualTo("oauth2-resource")
      assertThat(token.get("auth_source")).isEqualTo("none")
      assertThat(token.get("grant_type")).isEqualTo("client_credentials")
      assertThat(token.get("authorities")).isEqualTo(JSONArray(listOf("ROLE_AUDIT", "ROLE_OAUTH_ADMIN", "ROLE_TESTING")))

      assertThat(token.get("database_username")).isEqualTo("testy-db")
      assertThat(token.get("user_name")).isEqualTo("testy")
    }

    @Test
    fun `auth source passed in`() {
      val clientCredentialsResponse = webTestClient
        .post().uri("/oauth2/token?grant_type=client_credentials&auth_source=delius")
        .header(
          HttpHeaders.AUTHORIZATION,
          "Basic " + Base64.getEncoder().encodeToString(("test-client-create-id:test-secret").toByteArray()),
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .returnResult().responseBody

      val token = getTokenPayload(String(clientCredentialsResponse!!))
      assertThat(token.get("sub")).isEqualTo("test-client-create-id")
      assertThat(token.get("aud")).isEqualTo("oauth2-resource")
      assertThat(token.get("auth_source")).isEqualTo("delius")
      assertThat(token.get("grant_type")).isEqualTo("client_credentials")
      assertTrue(token.isNull("authorities"))

      assertTrue(token.isNull("user_name"))
      assertTrue(token.isNull("database_username"))
    }

    @Test
    fun `unrecognised auth source passed in`() {
      val clientCredentialsResponse = webTestClient
        .post().uri("/oauth2/token?grant_type=client_credentials&auth_source=xdelius")
        .header(
          HttpHeaders.AUTHORIZATION,
          "Basic " + Base64.getEncoder().encodeToString(("test-client-create-id:test-secret").toByteArray()),
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .returnResult().responseBody

      val token = getTokenPayload(String(clientCredentialsResponse))
      assertThat(token.get("sub")).isEqualTo("test-client-create-id")
      assertThat(token.get("aud")).isEqualTo("oauth2-resource")
      assertThat(token.get("auth_source")).isEqualTo("none")
      assertThat(token.get("grant_type")).isEqualTo("client_credentials")
      assertTrue(token.isNull("authorities"))

      assertTrue(token.isNull("user_name"))
      assertTrue(token.isNull("database_username"))
    }

    @Test
    fun `incorrect secret`() {
      webTestClient
        .post().uri("/oauth2/token?grant_type=client_credentials")
        .header(HttpHeaders.AUTHORIZATION, "Basic " + Base64.getEncoder().encodeToString(("test-client-id:test-secretx").toByteArray()))
        .exchange()
        .expectStatus().isUnauthorized

      verify(telemetryClient).trackEvent(
        "AuthorizationServerCreateAccessTokenFailure",
        mapOf("clientId" to "test-client-id", "clientIpAddress" to "127.0.0.1"),
        null,
      )
    }

    @Test
    fun `unrecognised client id`() {
      webTestClient
        .post().uri("/oauth2/token?grant_type=client_credentials")
        .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("unrecognised-client-id:test-secret").toByteArray()))
        .exchange()
        .expectStatus().isUnauthorized

      verify(telemetryClient).trackEvent(
        "AuthorizationServerCreateAccessTokenFailure",
        mapOf("clientId" to "unrecognised-client-id", "clientIpAddress" to "127.0.0.1"),
        null,
      )
    }

    @Test
    fun `anonymous token request`() {
      webTestClient
        .post().uri("/oauth2/token?grant_type=client_credentials")
        .exchange()
        .expectStatus().isUnauthorized
    }
  }

  private fun getTokenPayload(response: String): JSONObject {
    val accessToken = JSONObject(response).get("access_token") as String
    val tokenParts = accessToken.split(".")
    return JSONObject(String(Base64.getDecoder().decode(tokenParts[1])))
  }
}
