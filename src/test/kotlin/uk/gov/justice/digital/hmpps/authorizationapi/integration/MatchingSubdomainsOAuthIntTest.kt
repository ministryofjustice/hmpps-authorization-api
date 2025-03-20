package uk.gov.justice.digital.hmpps.authorizationapi.integration

import io.jsonwebtoken.Jwts
import org.hamcrest.CoreMatchers.allOf
import org.hamcrest.CoreMatchers.containsString
import org.hamcrest.CoreMatchers.startsWith
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.test.context.TestPropertySource
import uk.gov.justice.digital.hmpps.authorizationapi.service.AuthSource
import uk.gov.justice.digital.hmpps.authorizationapi.service.JWKKeyAccessor
import java.time.Duration
import java.util.Date

@TestPropertySource(properties = ["application.authentication.match-subdomains = true"])
class MatchingSubdomainsOAuthIntTest : IntegrationTestBase() {

  @Autowired
  private lateinit var jwkKeyAccessor: JWKKeyAccessor

  private val validRedirectUriWithSubdomain = "https://sub1.oauth.pstmn.io/v1/callback"
  private val validClientId = "test-auth-code-client"
  private val state = "1234"

  @Test
  fun `success redirects with code`() {
    webTestClient
      .get()
      .uri("/oauth2/authorize?response_type=code&client_id=$validClientId&state=$state&redirect_uri=$validRedirectUriWithSubdomain")
      .header("Authorization", createClientCredentialsTokenHeader())
      .cookie("jwtSession", createAuthenticationJwt())
      .exchange()
      .expectStatus().isFound
      .expectHeader()
      .value("Location", allOf(startsWith(validRedirectUriWithSubdomain), containsString("state=$state"), containsString("code=")))
  }

  private fun createClientCredentialsTokenHeader(): String {
    val authoritiesAsString = "ROLE_OAUTH_AUTHORIZE"

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

  private fun createAuthenticationJwt(): String {
    val authoritiesAsString = "ROLE_TESTING,ROLE_MORE_TESTING"
    return Jwts.builder()
      .id("1234-5678-9876-5432")
      .subject("username")
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
