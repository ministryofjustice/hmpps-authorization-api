package uk.gov.justice.digital.hmpps.authorizationserver.integration

import org.assertj.core.api.Assertions.assertThat
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.http.HttpHeaders
import java.util.Base64

class OAuthIntTest : IntegrationTestBase() {

  @Test
  fun `client credentials token request - client with database username`() {
    val clientCredentialsResponse = webTestClient
      .post().uri("/oauth2/token?grant_type=client_credentials")
      .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("test-client-id:test-secret").toByteArray()))
      .exchange()
      .expectStatus().isOk
      .expectBody()
      .jsonPath("$").value<Map<String, Any>> {
        assertThat(it).containsKey("expires_in")
        assertThat(it["expires_in"] as Int).isLessThan(301)
      }
      .returnResult().responseBody

    val payload = getTokenPayload(String(clientCredentialsResponse))
    assertThat(payload.get("sub")).isEqualTo("test-client-id")
    assertThat(payload.get("auth_source")).isEqualTo("none")
    assertThat(payload.get("database_username")).isEqualTo("testy-db")
    assertTrue(payload.isNull("user_name"))
  }

  @Test
  fun `client credentials token request - client without database username`() {
    val clientCredentialsResponse = webTestClient
      .post().uri("/oauth2/token?grant_type=client_credentials")
      .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("ip-allow-a-client-1:test-secret").toByteArray()))
      .exchange()
      .expectStatus().isOk
      .expectBody()
      .jsonPath("$").value<Map<String, Any>> {
        assertThat(it).containsKey("expires_in")
        assertThat(it["expires_in"] as Int).isLessThan(301)
      }
      .returnResult().responseBody

    val payload = getTokenPayload(String(clientCredentialsResponse))
    assertThat(payload.get("sub")).isEqualTo("ip-allow-a-client-1")
    assertThat(payload.get("auth_source")).isEqualTo("none")
    assertTrue(payload.isNull("database_username"))
    assertTrue(payload.isNull("user_name"))
  }

  @Test
  fun `client credentials token request with user name`() {
    val clientCredentialsResponse = webTestClient
      .post().uri("/oauth2/token?grant_type=client_credentials&username=testy")
      .header(
        HttpHeaders.AUTHORIZATION,
        "Basic " + Base64.getEncoder().encodeToString(("test-client-create-id:test-secret").toByteArray()),
      )
      .exchange()
      .expectStatus().isOk
      .expectBody()
      .returnResult().responseBody

    val payload = getTokenPayload(String(clientCredentialsResponse))
    assertThat(payload.get("sub")).isEqualTo("testy")
    assertThat(payload.get("user_name")).isEqualTo("testy")
  }

  @Test
  fun `client credentials token request with auth source`() {
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

    val payload = getTokenPayload(String(clientCredentialsResponse))
    assertThat(payload.get("auth_source")).isEqualTo("delius")
  }

  @Test
  fun `client credentials token request with unrecognised auth source`() {
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

    val payload = getTokenPayload(String(clientCredentialsResponse))
    assertThat(payload.get("auth_source")).isEqualTo("none")
  }

  @Test
  fun `client credentials login - incorrect secret`() {
    webTestClient
      .post().uri("/oauth2/token?grant_type=client_credentials")
      .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("test-client-id:test-secretx").toByteArray()))
      .exchange()
      .expectStatus().isUnauthorized
  }

  @Test
  fun `client credentials login - unrecognised client id`() {
    webTestClient
      .post().uri("/oauth2/token?grant_type=client_credentials")
      .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("unrecognised-client-id:test-secret").toByteArray()))
      .exchange()
      .expectStatus().isUnauthorized
  }

  @Test
  fun `client credentials - anonymous token request`() {
    webTestClient
      .post().uri("/oauth2/token?grant_type=client_credentials")
      .exchange()
      .expectStatus().isUnauthorized
  }

  private fun getTokenPayload(response: String): JSONObject {
    val accessToken = JSONObject(response).get("access_token") as String
    val tokenParts = accessToken.split(".")
    return JSONObject(String(Base64.getDecoder().decode(tokenParts[1])))
  }
}
