package uk.gov.justice.digital.hmpps.authorizationapi.integration

import com.microsoft.applicationinsights.TelemetryClient
import io.jsonwebtoken.Jwts
import org.assertj.core.api.Assertions
import org.assertj.core.api.Assertions.assertThat
import org.hamcrest.CoreMatchers.allOf
import org.hamcrest.CoreMatchers.containsString
import org.hamcrest.CoreMatchers.startsWith
import org.json.JSONArray
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.mockito.kotlin.verify
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.test.context.bean.override.mockito.MockitoBean
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.reactive.function.BodyInserters.fromFormData
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientRepository
import uk.gov.justice.digital.hmpps.authorizationapi.service.AuthSource
import uk.gov.justice.digital.hmpps.authorizationapi.service.GrantType
import uk.gov.justice.digital.hmpps.authorizationapi.service.JWKKeyAccessor
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.LocalDate
import java.util.Base64
import java.util.Date

class OAuthIntTest : IntegrationTestBase() {

  @Autowired
  private lateinit var jwkKeyAccessor: JWKKeyAccessor

  @Autowired
  private lateinit var userAuthenticationService: OAuth2AuthorizationService

  @Autowired
  private lateinit var clientRepository: ClientRepository

  @MockitoBean
  private lateinit var telemetryClient: TelemetryClient

  @Nested
  inner class ClientCredentials {

    @Test
    fun `client with database username`() {
      val clientCredentialsResponse = webTestClient
        .post().uri("/oauth2/token")
        .header(
          "Authorization",
          "Basic " + Base64.getEncoder().encodeToString(("test-client-id:test-secret").toByteArray()),
        )
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData("grant_type", "client_credentials"),
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("$").value<Map<String, Any>> {
          assertThat(it["expires_in"] as Int).isLessThan(1201)
          assertThat(it["sub"] as String).isEqualTo("test-client-id")
          assertThat(it["auth_source"] as String).isEqualTo("none")
          assertThat(it["token_type"] as String).isEqualTo("Bearer")
          assertThat(it["iss"] as String).isEqualTo("http://localhost:9090/auth/issuer")
          assertThat(it["jti"]).isNotNull
          assertThat(it["scope"] as String).isEqualTo("read write")
        }
        .returnResult().responseBody

      val token = getTokenPayload(String(clientCredentialsResponse!!))
      assertThat(token.get("sub")).isEqualTo("test-client-id")
      assertThat(token.get("auth_source")).isEqualTo("none")
      assertThat(token.get("grant_type")).isEqualTo("client_credentials")
      assertThat(token.get("authorities").toString()).isEqualTo(
        JSONArray(
          listOf(
            "ROLE_AUDIT",
            "ROLE_OAUTH_ADMIN",
            "ROLE_TESTING",
            "ROLE_VIEW_AUTH_SERVICE_DETAILS",
          ),
        ).toString(),
      )

      assertThat(token.get("database_username")).isEqualTo("testy-db")
      assertTrue(token.isNull("user_name"))
      verifyClaimNotPresentIn(token, "aud")
    }

    @Test
    fun `client without database username`() {
      val clientCredentialsResponse = webTestClient
        .post().uri("/oauth2/token")
        .header(
          "Authorization",
          "Basic " + Base64.getEncoder().encodeToString(("ip-allow-a-client-1:test-secret").toByteArray()),
        )
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData("grant_type", "client_credentials"),
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("$").value<Map<String, Any>> {
          assertThat(it["expires_in"] as Int).isLessThan(1201)
        }
        .returnResult().responseBody

      val token = getTokenPayload(String(clientCredentialsResponse!!))
      assertThat(token.get("sub")).isEqualTo("ip-allow-a-client-1")
      assertThat(token.get("auth_source")).isEqualTo("none")
      assertThat(token.get("grant_type")).isEqualTo("client_credentials")
      assertThat(token.get("iss")).isEqualTo("http://localhost:9090/auth/issuer")

      verifyClaimNotPresentIn(token, "database_username")
      verifyClaimNotPresentIn(token, "user_name")
      verifyClaimNotPresentIn(token, "aud")
    }

    @Test
    fun `user name passed in`() {
      val map = LinkedMultiValueMap<String, String>()
      map.add("grant_type", "client_credentials")
      map.add("username", "testy")
      val clientCredentialsResponse = webTestClient
        .post().uri("/oauth2/token")
        .header(
          HttpHeaders.AUTHORIZATION,
          "Basic " + Base64.getEncoder().encodeToString(("test-client-id:test-secret").toByteArray()),
        )
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData(map),
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .returnResult().responseBody

      val token = getTokenPayload(String(clientCredentialsResponse!!))
      assertThat(token.get("sub")).isEqualTo("testy")
      assertThat(token.get("auth_source")).isEqualTo("none")
      assertThat(token.get("grant_type")).isEqualTo("client_credentials")
      assertThat(token.get("authorities").toString()).isEqualTo(
        JSONArray(
          listOf(
            "ROLE_AUDIT",
            "ROLE_OAUTH_ADMIN",
            "ROLE_TESTING",
            "ROLE_VIEW_AUTH_SERVICE_DETAILS",
          ),
        ).toString(),
      )
      assertThat(token.get("iss")).isEqualTo("http://localhost:9090/auth/issuer")

      assertThat(token.get("database_username")).isEqualTo("testy-db")
      assertThat(token.get("user_name")).isEqualTo("testy")
      verifyClaimNotPresentIn(token, "aud")
    }

    @Test
    fun `updates last accessed date when null and suppresses update when already set to today`() {
      var client = clientRepository.findClientByClientId("last-accessed-date-test-client")
      assertThat(client!!.lastAccessedDate).isNull()

      webTestClient
        .post().uri("/oauth2/token")
        .header(
          "Authorization",
          "Basic " + Base64.getEncoder().encodeToString(("last-accessed-date-test-client:test-secret").toByteArray()),
        )
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData("grant_type", "client_credentials"),
        )
        .exchange()
        .expectStatus().isOk

      client = clientRepository.findClientByClientId("last-accessed-date-test-client")
      val lastAccessedDate = client!!.lastAccessedDate

      assertThat(lastAccessedDate).isNotNull
      assertThat(lastAccessedDate!!.toLocalDate()).isEqualTo(LocalDate.now())

      webTestClient
        .post().uri("/oauth2/token")
        .header(
          "Authorization",
          "Basic " + Base64.getEncoder().encodeToString(("last-accessed-date-test-client:test-secret").toByteArray()),
        )
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData("grant_type", "client_credentials"),
        )
        .exchange()
        .expectStatus().isOk

      client = clientRepository.findClientByClientId("last-accessed-date-test-client")
      assertThat(client!!.lastAccessedDate).isEqualTo(lastAccessedDate)
    }

    @Test
    fun `updates last accessed when before today`() {
      var client = clientRepository.findClientByClientId("last-accessed-in-the-past-test-client")
      assertThat(client!!.lastAccessedDate!!.toLocalDate()).isBefore(LocalDate.now())

      webTestClient
        .post().uri("/oauth2/token")
        .header(
          "Authorization",
          "Basic " + Base64.getEncoder().encodeToString(("last-accessed-in-the-past-test-client:test-secret").toByteArray()),
        )
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData("grant_type", "client_credentials"),
        )
        .exchange()
        .expectStatus().isOk

      client = clientRepository.findClientByClientId("last-accessed-in-the-past-test-client")
      val lastAccessedDate = client!!.lastAccessedDate

      assertThat(lastAccessedDate).isNotNull
      assertThat(lastAccessedDate!!.toLocalDate()).isEqualTo(LocalDate.now())
    }

    @Test
    fun `auth source passed in`() {
      val map = LinkedMultiValueMap<String, String>()
      map.add("grant_type", "client_credentials")
      map.add("auth_source", "delius")
      val clientCredentialsResponse = webTestClient
        .post().uri("/oauth2/token")
        .header(
          HttpHeaders.AUTHORIZATION,
          "Basic " + Base64.getEncoder().encodeToString(("test-client-create-id:test-secret").toByteArray()),
        )
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData(map),
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .returnResult().responseBody

      val token = getTokenPayload(String(clientCredentialsResponse!!))
      assertThat(token.get("sub")).isEqualTo("test-client-create-id")
      assertThat(token.get("auth_source")).isEqualTo("delius")
      assertThat(token.get("iss")).isEqualTo("http://localhost:9090/auth/issuer")
      assertThat(token.get("grant_type")).isEqualTo("client_credentials")
      assertTrue(token.isNull("authorities"))

      assertTrue(token.isNull("user_name"))
      assertTrue(token.isNull("database_username"))
      verifyClaimNotPresentIn(token, "aud")
    }

    @Test
    fun `unrecognised auth source passed in`() {
      val map = LinkedMultiValueMap<String, String>()
      map.add("grant_type", "client_credentials")
      map.add("auth_source", "xdelius")
      val clientCredentialsResponse = webTestClient
        .post().uri("/oauth2/token")
        .header(
          HttpHeaders.AUTHORIZATION,
          "Basic " + Base64.getEncoder().encodeToString(("test-client-create-id:test-secret").toByteArray()),
        )
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData(map),
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .returnResult().responseBody

      val token = getTokenPayload(String(clientCredentialsResponse))
      assertThat(token.get("sub")).isEqualTo("test-client-create-id")
      assertThat(token.get("auth_source")).isEqualTo("none")
      assertThat(token.get("grant_type")).isEqualTo("client_credentials")
      assertTrue(token.isNull("authorities"))

      assertTrue(token.isNull("user_name"))
      assertTrue(token.isNull("database_username"))
      verifyClaimNotPresentIn(token, "aud")
    }

    @Test
    fun `incorrect secret`() {
      webTestClient
        .post().uri("/oauth2/token")
        .header(
          HttpHeaders.AUTHORIZATION,
          "Basic " + Base64.getEncoder().encodeToString(("test-client-id:test-secretx").toByteArray()),
        )
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData("grant_type", "client_credentials"),
        )
        .exchange()
        .expectStatus().isUnauthorized

      verify(telemetryClient).trackEvent(
        "AuthorizationApiCreateAccessTokenFailure",
        mapOf("clientId" to "test-client-id", "clientIpAddress" to "127.0.0.1"),
        null,
      )
    }

    @Test
    fun `unrecognised client id`() {
      webTestClient
        .post().uri("/oauth2/token")
        .header(
          "Authorization",
          "Basic " + Base64.getEncoder().encodeToString(("unrecognised-client-id:test-secret").toByteArray()),
        )
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData("grant_type", "client_credentials"),
        )
        .exchange()
        .expectStatus().isUnauthorized

      verify(telemetryClient).trackEvent(
        "AuthorizationApiCreateAccessTokenFailure",
        mapOf("clientId" to "unrecognised-client-id", "clientIpAddress" to "127.0.0.1"),
        null,
      )
    }

    @Test
    fun `client with no authorities in authorization consent`() {
      webTestClient
        .post().uri("/oauth2/token")
        .header(
          "Authorization",
          "Basic " + Base64.getEncoder().encodeToString(("no-authorities:clientsecret").toByteArray()),
        )
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData("grant_type", "client_credentials"),
        )
        .exchange()
        .expectStatus().isOk
    }

    @Test
    fun `anonymous token request`() {
      webTestClient
        .post().uri("/oauth2/token")
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData("grant_type", "client_credentials"),
        )
        .exchange()
        .expectStatus().isUnauthorized
    }

    @Test
    fun `url encoded credentials handled`() {
      val urlEncodedClientId = URLEncoder.encode("url-encode-client-credentials", StandardCharsets.UTF_8.toString())
      val urlEncodedSecret = URLEncoder.encode("test>secret", StandardCharsets.UTF_8.toString())

      val clientCredentialsResponse = webTestClient
        .post().uri("/oauth2/token")
        .header(
          "Authorization",
          "Basic " + Base64.getEncoder().encodeToString(("$urlEncodedClientId:$urlEncodedSecret").toByteArray()),
        )
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData("grant_type", "client_credentials"),
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("$").value<Map<String, Any>> {
          assertThat(it["expires_in"] as Int).isLessThan(1201)
        }
        .returnResult().responseBody

      val token = getTokenPayload(String(clientCredentialsResponse!!))
      assertThat(token.get("sub")).isEqualTo("url-encode-client-credentials")
    }

    @Test
    fun `url encoded credentials longer than 72 bytes encoded handled`() {
      val urlEncodedClientId = URLEncoder.encode("long-encoded-client-credentials", StandardCharsets.UTF_8.toString())
      val urlEncodedSecret = URLEncoder.encode("zK*AWM.,7QutO&hG(jp:L!&3DRyK13sjXR5aO(2x+kPjhCJ34wE&b*:mHn", StandardCharsets.UTF_8.toString())

      val clientCredentialsResponse = webTestClient
        .post().uri("/oauth2/token")
        .header(
          "Authorization",
          "Basic " + Base64.getEncoder().encodeToString(("$urlEncodedClientId:$urlEncodedSecret").toByteArray()),
        )
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData("grant_type", "client_credentials"),
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("$").value<Map<String, Any>> {
          assertThat(it["expires_in"] as Int).isLessThan(1201)
        }
        .returnResult().responseBody

      val token = getTokenPayload(String(clientCredentialsResponse!!))
      assertThat(token.get("sub")).isEqualTo("long-encoded-client-credentials")
    }

    @Test
    fun `Incorrect secret with invalid url encoded characters`() {
      webTestClient
        .post().uri("/oauth2/token")
        .header(
          HttpHeaders.AUTHORIZATION,
          "Basic " + Base64.getEncoder().encodeToString(("test-client-id:test-secret%Y").toByteArray()),
        )
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData("grant_type", "client_credentials"),
        )
        .exchange()
        .expectStatus().isUnauthorized

      verify(telemetryClient).trackEvent(
        "AuthorizationApiCreateAccessTokenFailure",
        mapOf("clientId" to "test-client-id", "clientIpAddress" to "127.0.0.1"),
        null,
      )
    }
  }

  @Nested
  inner class AuthorizationCode {

    private val validRedirectUri = "http://127.0.0.1:8089/login/oauth2/code/oidc-client"
    private val invalidRedirectUri = "http://127.0.0.1:8089/login/oauth2/code/oidc-client-x"
    private val validClientId = "test-auth-code-client"
    private val invalidClientId = "test-auth-code-client-x"
    private val state = "1234"

    @Test
    fun `unauthenticated user`() {
      webTestClient
        .get()
        .uri("/oauth2/authorize?response_type=code&client_id=$validClientId&state=$state&redirect_uri=$validRedirectUri")
        .header("Authorization", createClientCredentialsTokenHeader("ROLE_OAUTH_AUTHORIZE", "ROLE_OAUTH_ADMIN"))
        .exchange()
        .expectStatus().isUnauthorized
    }

    @Test
    fun `invalid client id`() {
      webTestClient
        .get()
        .uri("/oauth2/authorize?response_type=code&client_id=$invalidClientId&state=$state&redirect_uri=$validRedirectUri")
        .header("Authorization", createClientCredentialsTokenHeader("ROLE_OAUTH_AUTHORIZE", "ROLE_OAUTH_ADMIN"))
        .cookie("jwtSession", createAuthenticationJwt("username", "ROLE_TESTING", "ROLE_MORE_TESTING"))
        .exchange()
        .expectStatus().isBadRequest
    }

    @Test
    fun `invalid redirect url`() {
      webTestClient
        .get()
        .uri("/oauth2/authorize?response_type=code&client_id=$validClientId&state=$state&redirect_uri=$invalidRedirectUri")
        .header("Authorization", createClientCredentialsTokenHeader("ROLE_OAUTH_AUTHORIZE"))
        .cookie("jwtSession", createAuthenticationJwt("username", "ROLE_TESTING", "ROLE_MORE_TESTING"))
        .exchange()
        .expectStatus().isBadRequest
    }

    @Test
    fun `missing response type`() {
      webTestClient
        .get().uri("/oauth2/authorize?client_id=$validClientId&state=$state&redirect_uri=$validRedirectUri")
        .header("Authorization", createClientCredentialsTokenHeader("ROLE_OAUTH_AUTHORIZE"))
        .cookie("jwtSession", createAuthenticationJwt("username", "ROLE_TESTING", "ROLE_MORE_TESTING"))
        .exchange()
        .expectStatus().isBadRequest
    }

    @Test
    fun `missing client credentials token`() {
      webTestClient
        .get()
        .uri("/oauth2/authorize?response_type=code&client_id=$validClientId&state=$state&redirect_uri=$validRedirectUri")
        .cookie("jwtSession", createAuthenticationJwt("username", "ROLE_TESTING", "ROLE_MORE_TESTING"))
        .exchange()
        .expectStatus().isUnauthorized
    }

    @Test
    fun `incorrect authority`() {
      webTestClient
        .get()
        .uri("/oauth2/authorize?response_type=code&client_id=$validClientId&state=$state&redirect_uri=$validRedirectUri")
        .header("Authorization", createClientCredentialsTokenHeader("ROLE_NOT_AUTHORIZE"))
        .cookie("jwtSession", createAuthenticationJwt("username", "ROLE_TESTING", "ROLE_MORE_TESTING"))
        .exchange()
        .expectStatus().isUnauthorized
    }

    @Test
    fun `no authority`() {
      webTestClient
        .get()
        .uri("/oauth2/authorize?response_type=code&client_id=$validClientId&state=$state&redirect_uri=$validRedirectUri")
        .header("Authorization", createClientCredentialsTokenHeader())
        .cookie("jwtSession", createAuthenticationJwt("username", "ROLE_TESTING", "ROLE_MORE_TESTING"))
        .exchange()
        .expectStatus().isUnauthorized
    }

    @Test
    fun `success redirects with code and updates last accessed date when null and suppresses update when already set to today`() {
      var client = clientRepository.findClientByClientId("hmpps-authorization-client")
      assertThat(client!!.lastAccessedDate).isNull()

      webTestClient
        .get()
        .uri("/oauth2/authorize?response_type=code&client_id=hmpps-authorization-client&state=$state&redirect_uri=http://localhost:3002/sign-in/callback")
        .header("Authorization", createClientCredentialsTokenHeader("ROLE_OAUTH_AUTHORIZE"))
        .cookie("jwtSession", createAuthenticationJwt("username", "ROLE_TESTING", "ROLE_MORE_TESTING"))
        .exchange()
        .expectStatus().isFound
        .expectHeader()
        .value("Location", allOf(startsWith("http://localhost:3002/sign-in/callback"), containsString("state=$state"), containsString("code=")))

      client = clientRepository.findClientByClientId("hmpps-authorization-client")
      var lastAccessedDate = client!!.lastAccessedDate
      assertThat(lastAccessedDate).isNotNull
      assertThat(lastAccessedDate!!.toLocalDate()).isEqualTo(LocalDate.now())

      webTestClient
        .get()
        .uri("/oauth2/authorize?response_type=code&client_id=hmpps-authorization-client&state=$state&redirect_uri=http://localhost:3002/sign-in/callback")
        .header("Authorization", createClientCredentialsTokenHeader("ROLE_OAUTH_AUTHORIZE"))
        .cookie("jwtSession", createAuthenticationJwt("username", "ROLE_TESTING", "ROLE_MORE_TESTING"))
        .exchange()
        .expectStatus().isFound

      client = clientRepository.findClientByClientId("hmpps-authorization-client")
      assertThat(lastAccessedDate).isEqualTo(lastAccessedDate)
    }

    @Test
    fun `success updates last accessed date when before today`() {
      var client = clientRepository.findClientByClientId("last-accessed-in-the-past-hmpps-authorization-client")
      assertThat(client!!.lastAccessedDate!!.toLocalDate()).isBefore(LocalDate.now())

      webTestClient
        .get()
        .uri("/oauth2/authorize?response_type=code&client_id=last-accessed-in-the-past-hmpps-authorization-client&state=$state&redirect_uri=http://localhost:3002/sign-in/callback")
        .header("Authorization", createClientCredentialsTokenHeader("ROLE_OAUTH_AUTHORIZE"))
        .cookie("jwtSession", createAuthenticationJwt("username", "ROLE_TESTING", "ROLE_MORE_TESTING"))
        .exchange()
        .expectStatus().isFound
        .expectHeader()
        .value("Location", allOf(startsWith("http://localhost:3002/sign-in/callback"), containsString("state=$state"), containsString("code=")))

      client = clientRepository.findClientByClientId("last-accessed-in-the-past-hmpps-authorization-client")
      var lastAccessedDate = client!!.lastAccessedDate
      assertThat(lastAccessedDate).isNotNull
      assertThat(lastAccessedDate!!.toLocalDate()).isEqualTo(LocalDate.now())
    }

    @Test
    fun `authorization code is valid for the default duration when no override has been defined`() {
      val location = webTestClient
        .get()
        .uri("/oauth2/authorize?response_type=code&client_id=$validClientId&state=$state&redirect_uri=$validRedirectUri")
        .header("Authorization", createClientCredentialsTokenHeader("ROLE_OAUTH_AUTHORIZE"))
        .cookie("jwtSession", createAuthenticationJwt("username", "ROLE_TESTING", "ROLE_MORE_TESTING"))
        .exchange()
        .expectStatus().isFound
        .expectHeader()
        .value("Location", allOf(startsWith(validRedirectUri), containsString("state=$state"), containsString("code=")))
        .returnResult(String::class.java)

      val groups: MatchResult? = ".*code=(.*)&state=.*".toRegex().find(location.responseHeaders.location!!.toString())
      assertThat(groups).isNotNull
      assertThat(groups!!.groupValues).hasSizeGreaterThan(1)
      assertThat(groups.groups[1]?.value).isNotNull

      val code = groups.groups[1]!!.value
      val authCodeToken = userAuthenticationService.findByToken(code, OAuth2TokenType(OAuth2ParameterNames.CODE))?.let {
        it.getToken(OAuth2AuthorizationCode::class.java)?.token
      }

      val diff = Duration.between(authCodeToken!!.issuedAt, authCodeToken.expiresAt)

      // test client is created with an auth code ttl of 20 mins. See resources/db/dev/data/V900_0__registered_clients.sql
      val expectedAuthCodeTtlDuration = Duration.ofMinutes(20)
      assertThat(diff).isEqualTo(expectedAuthCodeTtlDuration)
    }

    @Test
    fun `code convert to token`() {
      var header: String? = null
      webTestClient
        .get()
        .uri("/oauth2/authorize?response_type=code&client_id=$validClientId&state=$state&redirect_uri=$validRedirectUri")
        .header("Authorization", createClientCredentialsTokenHeader("ROLE_OAUTH_AUTHORIZE"))
        .cookie("jwtSession", createAuthenticationJwt("username", "ROLE_TESTING", "ROLE_MORE_TESTING"))
        .exchange()
        .expectHeader()
        .value("Location") { h: String -> header = h }

      val authorisationCode =
        header!!.substringAfter("?").split("&").first { it.startsWith("code=") }.substringAfter("code=")

      val formData = LinkedMultiValueMap<String, String>().apply {
        add("grant_type", "authorization_code")
        add("code", authorisationCode)
        add("state", state)
        add("redirect_uri", validRedirectUri)
      }

      val tokenResponse = webTestClient
        .post().uri("/oauth2/token")
        .header(
          "Authorization",
          "Basic " + Base64.getEncoder().encodeToString(("$validClientId:test-secret").toByteArray()),
        )
        .contentType(APPLICATION_FORM_URLENCODED)
        .bodyValue(
          formData,
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .returnResult().responseBody

      val fullJsonResponse = JSONObject(String(tokenResponse!!))
      assertThat(fullJsonResponse.get("sub")).isEqualTo("username")
      assertThat(fullJsonResponse.get("user_uuid")).isEqualTo("1234-5678-9999-1111")
      assertThat(fullJsonResponse.get("user_id")).isEqualTo("9999")
      assertThat(fullJsonResponse.get("user_name")).isEqualTo("username")
      assertThat(fullJsonResponse.get("auth_source")).isEqualTo(AuthSource.Auth.name.lowercase())
      assertThat(fullJsonResponse.get("scope")).isEqualTo("read")
      assertThat(fullJsonResponse.get("iss")).isEqualTo("http://localhost:9090/auth/issuer")
      assertThat(fullJsonResponse.get("token_type")).isEqualTo("Bearer")
      assertThat(fullJsonResponse.get("expires_in")).isNotNull
      assertThat(fullJsonResponse.get("jti")).isNotNull
      assertThat(fullJsonResponse.get("jwt_id")).isEqualTo("1234-5678-9876-5432")

      val token = getTokenPayload(String(tokenResponse))
      assertThat(token.get("authorities").toString()).isEqualTo(
        JSONArray(
          listOf(
            "ROLE_TESTING",
            "ROLE_MORE_TESTING",
          ),
        ).toString(),
      )
      assertThat(token.get("sub")).isEqualTo("username")
      assertThat(token.get("client_id")).isEqualTo(validClientId)
      assertThat(token.get("grant_type")).isEqualTo(GrantType.authorization_code.name)
      assertThat(token.get("auth_source")).isEqualTo(AuthSource.Auth.name.lowercase())
      assertThat(token.get("scope").toString()).isEqualTo(JSONArray(listOf("read")).toString())
      assertThat(token.get("user_id")).isEqualTo("9999")
      assertThat(token.get("name")).isEqualTo("name")
      assertThat(fullJsonResponse.get("user_name")).isEqualTo("username")
      assertThat(token.get("user_uuid")).isEqualTo("1234-5678-9999-1111")
      assertThat(token.get("jwt_id")).isEqualTo("1234-5678-9876-5432")

      verifyClaimNotPresentIn(token, "aud")
    }

    @Test
    fun `code convert to token using url encoded credentials`() {
      val urlEncodedClientId = URLEncoder.encode("url-encode-auth-code", StandardCharsets.UTF_8.toString())
      val urlEncodedSecret = URLEncoder.encode("test>secret", StandardCharsets.UTF_8.toString())

      var header: String? = null
      webTestClient
        .get()
        .uri("/oauth2/authorize?response_type=code&client_id=$urlEncodedClientId&state=$state&redirect_uri=$validRedirectUri")
        .header("Authorization", createClientCredentialsTokenHeader("ROLE_OAUTH_AUTHORIZE"))
        .cookie("jwtSession", createAuthenticationJwt("username", "ROLE_TESTING", "ROLE_MORE_TESTING"))
        .exchange()
        .expectHeader()
        .value("Location") { h: String -> header = h }

      val authorisationCode =
        header!!.substringAfter("?").split("&").first { it.startsWith("code=") }.substringAfter("code=")

      val formData = LinkedMultiValueMap<String, String>().apply {
        add("grant_type", "authorization_code")
        add("code", authorisationCode)
        add("state", state)
        add("redirect_uri", validRedirectUri)
      }

      val tokenResponse = webTestClient
        .post().uri("/oauth2/token")
        .header(
          "Authorization",
          "Basic " + Base64.getEncoder().encodeToString(("$urlEncodedClientId:$urlEncodedSecret").toByteArray()),
        )
        .contentType(APPLICATION_FORM_URLENCODED)
        .bodyValue(
          formData,
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .returnResult().responseBody

      val token = getTokenPayload(String(tokenResponse))
      assertThat(token.get("client_id")).isEqualTo(urlEncodedClientId)
    }

    @Test
    fun `confirm jwt fields are removed from claims and access token in authorization-code flow`() {
      val validClientId = "test-auth-code-client-with-jwt-settings"
      var header: String? = null
      webTestClient
        .get()
        .uri("/oauth2/authorize?response_type=code&client_id=$validClientId&state=$state&redirect_uri=$validRedirectUri")
        .header("Authorization", createClientCredentialsTokenHeader("ROLE_OAUTH_AUTHORIZE"))
        .cookie("jwtSession", createAuthenticationJwt("username", "ROLE_TESTING", "ROLE_MORE_TESTING"))
        .exchange()
        .expectHeader()
        .value("Location") { h: String -> header = h }

      val authorisationCode =
        header!!.substringAfter("?").split("&").first { it.startsWith("code=") }.substringAfter("code=")

      val formData = LinkedMultiValueMap<String, String>().apply {
        add("grant_type", "authorization_code")
        add("code", authorisationCode)
        add("state", state)
        add("redirect_uri", validRedirectUri)
      }

      val tokenResponse = webTestClient
        .post().uri("/oauth2/token")
        .header(
          "Authorization",
          "Basic " + Base64.getEncoder().encodeToString(("$validClientId:test-secret").toByteArray()),
        )
        .contentType(APPLICATION_FORM_URLENCODED)
        .bodyValue(
          formData,
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .returnResult().responseBody

      val fullJsonResponse = JSONObject(String(tokenResponse!!))

      assertThat(fullJsonResponse.get("sub")).isEqualTo("username")
      assertThat(fullJsonResponse.get("user_uuid")).isEqualTo("1234-5678-9999-1111")
      assertThat(fullJsonResponse.get("auth_source")).isEqualTo(AuthSource.Auth.name.lowercase())
      assertThat(fullJsonResponse.get("scope").toString()).isEqualTo("read")
      assertThat(fullJsonResponse.get("iss")).isEqualTo("http://localhost:9090/auth/issuer")
      assertThat(fullJsonResponse.get("token_type")).isEqualTo("Bearer")
      assertThat(fullJsonResponse.get("expires_in")).isNotNull
      assertThat(fullJsonResponse.get("jti")).isNotNull

      assertThat(fullJsonResponse.optString("user_id", null)).isNull()
      assertThat(fullJsonResponse.optString("user_name", null)).isNull()

      val token = getTokenPayload(String(tokenResponse))
      assertThat(token.get("authorities").toString()).isEqualTo(
        JSONArray(
          listOf(
            "ROLE_TESTING",
            "ROLE_MORE_TESTING",
          ),
        ).toString(),
      )
      assertThat(token.get("sub")).isEqualTo("username")

      assertThat(token.get("client_id")).isEqualTo(validClientId)
      assertThat(token.get("grant_type")).isEqualTo(GrantType.authorization_code.name)
      assertThat(token.get("auth_source")).isEqualTo(AuthSource.Auth.name.lowercase())
      assertThat(token.get("scope").toString()).isEqualTo(JSONArray(listOf("read")).toString())
      assertThat(token.get("user_uuid")).isEqualTo("1234-5678-9999-1111")
      assertThat(token.get("name")).isEqualTo("name")

      assertThat(token.optString("user_name", null)).isNull()
      assertThat(token.optString("user_id", null)).isNull()
    }

    private fun createClientCredentialsTokenHeader(vararg roles: String): String {
      val authoritiesAsString = roles.asList().joinToString(",")

      return "Bearer " + Jwts.builder()
        .id("1234")
        .claims(
          mapOf<String, Any>(
            "authorities" to authoritiesAsString,
            "name" to "name",
          ),
        )
        .expiration(Date(System.currentTimeMillis() + Duration.ofSeconds(500).toMillis()))
        .signWith(jwkKeyAccessor.getPrimaryKeyPair().private)
        .compact()
    }

    private fun createAuthenticationJwt(username: String, vararg roles: String): String {
      val authoritiesAsString = roles.asList().joinToString(",")
      return Jwts.builder()
        .id("1234-5678-9876-5432")
        .subject(username)
        .claims(
          mapOf<String, Any>(
            "authorities" to authoritiesAsString,
            "name" to "name",
            "auth_source" to AuthSource.Auth.name,
            "user_id" to "9999",
            "uuid" to "1234-5678-9999-1111",
          ),
        )
        .expiration(Date(System.currentTimeMillis() + Duration.ofSeconds(5).toMillis()))
        .signWith(jwkKeyAccessor.getPrimaryKeyPair().private)
        .compact()
    }
  }

  private fun verifyClaimNotPresentIn(token: JSONObject, claim: String) {
    Assertions.assertThatThrownBy {
      token.get(claim)
    }.hasMessage("JSONObject[\"$claim\"] not found.")
  }

  private fun getTokenPayload(response: String): JSONObject {
    val accessToken = JSONObject(response).get("access_token") as String
    val tokenParts = accessToken.split(".")
    return JSONObject(String(Base64.getDecoder().decode(tokenParts[1])))
  }
}
