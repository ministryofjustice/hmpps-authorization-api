package uk.gov.justice.digital.hmpps.authorizationserver.integration

import com.microsoft.applicationinsights.TelemetryClient
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.assertj.core.api.Assertions.assertThat
import org.json.JSONArray
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.mockito.kotlin.verify
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.http.HttpHeaders
import uk.gov.justice.digital.hmpps.authorizationserver.service.AuthSource
import uk.gov.justice.digital.hmpps.authorizationserver.service.JWKKeyAccessor
import java.time.Duration
import java.util.Base64
import java.util.Date

class OAuthIntTest : IntegrationTestBase() {

  @Autowired
  private lateinit var jwkKeyAccessor: JWKKeyAccessor

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

  @Nested
  inner class AuthorizationCode {

    @Test
    fun `unauthenticated user`() {
      webTestClient
        .get().uri("/oauth2/authorize?response_type=code&client_id=test-auth-code-client&state=1234&redirect_uri=http://127.0.0.1:8089/login/oauth2/code/oidc-client")
        .exchange()
        .expectStatus().isUnauthorized
    }

    @Test
    fun `invalid request - client id`() {
    }

    @Test
    fun `invalid request - redirect url`() {
    }

    @Test
    fun `invalid request - response type`() {
    }

    @Test
    fun `invalid request - state`() {
    }

    @Test
    fun `success redirects with code`() {
      webTestClient
        .get().uri("/oauth2/authorize?response_type=code&client_id=test-auth-code-client&state=1234&redirect_uri=http://127.0.0.1:8089/login/oauth2/code/oidc-client")
        .cookie("jwtSession", createAuthenticationJwt())
        .exchange()
        .expectStatus().isFound
        .expectHeader()
        .exists("Location")

      /*
      ACTUAL RESPONSE EXAMPLE

      < 302 FOUND Found
      < X-Content-Type-Options: [nosniff]
      < X-XSS-Protection: [0]
      < Cache-Control: [no-cache, no-store, max-age=0, must-revalidate]
      < Pragma: [no-cache]
      < Expires: [0]
      < X-Frame-Options: [DENY]
      < Location: [http://127.0.0.1:8089/login/oauth2/code/oidc-client?code=jSnFrrkyAHR537emb1ecK8mo00mKhszKuBGaRi8z11QGbhI7t1-9hEVLYKuTGL4HwWbpjct3vD-Vx_-_v4XjDQKFRGFfRY6k7uB3ZXKww7W2cgMiTk5qdM1hSevJJiXI&state=1234]
      < Content-Length: [0]
      < Date: [Thu, 08 Feb 2024 18:35:39 GMT]

       */
    }

    private fun createAuthenticationJwt(): String {
      val username = "username"
      val authoritiesAsString = "ROLE_TESTING,ROLE_MORE_TESTING"

      return Jwts.builder()
        .setId("1234")
        .setSubject(username)
        .addClaims(
          mapOf<String, Any>(
            "authorities" to authoritiesAsString,
            "name" to "name",
            "auth_source" to AuthSource.Auth.name,
            "user_id" to "9999",
            "passed_mfa" to true,
          ),
        )
        .setExpiration(Date(System.currentTimeMillis() + Duration.ofMinutes(5).toMillis()))
        .signWith(SignatureAlgorithm.RS256, jwkKeyAccessor.getPrimaryKeyPair().private)
        .compact()
    }
  }

  private fun getTokenPayload(response: String): JSONObject {
    val accessToken = JSONObject(response).get("access_token") as String
    val tokenParts = accessToken.split(".")
    return JSONObject(String(Base64.getDecoder().decode(tokenParts[1])))
  }
}
