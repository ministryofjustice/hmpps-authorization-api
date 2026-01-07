package uk.gov.justice.digital.hmpps.authorizationapi.service

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.within
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.ArgumentCaptor
import org.mockito.Captor
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.any
import org.mockito.kotlin.isNull
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import java.time.Instant
import java.time.temporal.ChronoUnit.SECONDS
import java.util.UUID

@ExtendWith(MockitoExtension::class)
class TokenResponseHandlerTest {

  @Mock
  private lateinit var oAuth2AccessTokenResponseHttpMessageConverter: OAuth2AccessTokenResponseHttpMessageConverter

  @Mock
  private lateinit var jwtDecoder: JwtDecoder

  @Mock
  private lateinit var request: HttpServletRequest

  @Mock
  private lateinit var response: HttpServletResponse

  @Mock
  private lateinit var authentication: OAuth2AccessTokenAuthenticationToken

  @Mock
  private lateinit var jwt: Jwt

  private lateinit var tokenResponseHandler: TokenResponseHandler

  private lateinit var issuedAt: Instant

  private lateinit var expiresAt: Instant

  @Captor
  private lateinit var tokenResponseMessageConverterCaptor: ArgumentCaptor<OAuth2AccessTokenResponse>

  companion object {
    val SCOPE_RW = setOf("read", "write")

    val ALL_CLAIMS = mapOf(
      "sub" to "AUTH_MFA_PREF_EMAIL4",
      "user_name" to "AUTH_MFA_PREF_EMAIL4",
      "auth_source" to "auth",
      "authorities" to listOf("ROLE_MFA"),
      "client_id" to "some-client-id",
      "iss" to "http://localhost/",
      "user_uuid" to "2e285ccd-dcfd-4497-9e22-d6e8e10a2d63",
      "grant_type" to "authorization_code",
      "user_id" to "3e285ccd-dcfd-4495-9e22-i6e8e10a2d63",
      "scope" to ArrayList<String>(SCOPE_RW),
      "name" to "Auth Mfa",
      "exp" to 1721752178,
      "jti" to "OvQBycPwvHpv3MYEOtnrn6P55F0",
    )
  }

  @BeforeEach
  fun setup() {
    issuedAt = Instant.now()
    expiresAt = issuedAt.plusSeconds(3600)

    tokenResponseHandler = TokenResponseHandler(oAuth2AccessTokenResponseHttpMessageConverter, jwtDecoder)
  }

  @Test
  fun `TokenResponseHandler adds the expected additional properties to the token response`() {
    val testJWT = createTestJwt(
      jwtId = UUID.randomUUID().toString(),
      claims = ALL_CLAIMS,
    )

    whenever(authentication.accessToken)
      .thenReturn(OAuth2AccessToken(TokenType.BEARER, testJWT, issuedAt, expiresAt, SCOPE_RW))

    whenever(jwtDecoder.decode(testJWT)).thenReturn(jwt)
    whenever(jwt.claims).thenReturn(ALL_CLAIMS)

    tokenResponseHandler.onAuthenticationSuccess(request, response, authentication)

    assertTokenResponseContainsExpectedValues(testJWT) { additionalParams ->
      assertThat(additionalParams["scope"]).isEqualTo(
        "read write",
      )
    }
  }

  @Nested
  inner class ScopeClaim {
    @Test
    fun `additional property scope is not added when it does not exist in the source access token`() {
      // Remove scope from the claims
      val claims = HashMap(ALL_CLAIMS)
      claims.remove("scope")

      val testJWT = createTestJwt(
        jwtId = UUID.randomUUID().toString(),
        claims = claims,
      )

      whenever(authentication.accessToken)
        .thenReturn(OAuth2AccessToken(TokenType.BEARER, testJWT, issuedAt, expiresAt, SCOPE_RW))
      whenever(jwtDecoder.decode(testJWT)).thenReturn(jwt)
      whenever(jwt.claims).thenReturn(claims)

      tokenResponseHandler.onAuthenticationSuccess(request, response, authentication)

      assertTokenResponseContainsExpectedValues(
        testJWT,
      ) { additionalParams -> assertThat(additionalParams).doesNotContainKey("scope") }
    }

    @Test
    fun `additional property scope is not added when scope is present with a null value in the source access token`() {
      // Update scope to have null value
      val claims = HashMap(ALL_CLAIMS)
      claims["scope"] = null

      val testJWT = createTestJwt(
        jwtId = UUID.randomUUID().toString(),
        claims = claims,
      )

      whenever(authentication.accessToken)
        .thenReturn(OAuth2AccessToken(TokenType.BEARER, testJWT, issuedAt, expiresAt, SCOPE_RW))
      whenever(jwtDecoder.decode(testJWT)).thenReturn(jwt)
      whenever(jwt.claims).thenReturn(claims)

      tokenResponseHandler.onAuthenticationSuccess(request, response, authentication)

      assertTokenResponseContainsExpectedValues(
        testJWT,
      ) { additionalParams -> assertThat(additionalParams).doesNotContainKey("scope") }
    }

    @Test
    fun `additional property scope is not present when scope is present with empty value in the source access token`() {
      // Update scope to have empty value
      val claims = HashMap(ALL_CLAIMS)
      claims["scope"] = emptyList<String>()

      val testJWT = createTestJwt(
        jwtId = UUID.randomUUID().toString(),
        claims = claims,
      )

      whenever(authentication.accessToken)
        .thenReturn(OAuth2AccessToken(TokenType.BEARER, testJWT, issuedAt, expiresAt, SCOPE_RW))
      whenever(jwtDecoder.decode(testJWT)).thenReturn(jwt)
      whenever(jwt.claims).thenReturn(claims)

      tokenResponseHandler.onAuthenticationSuccess(request, response, authentication)

      assertTokenResponseContainsExpectedValues(
        testJWT,
      ) { additionalParams -> assertThat(additionalParams).doesNotContainKey("scope") }
    }

    @Test
    fun `additional property scope is not present when scope in the source access token is not a list of strings`() {
      // Update scope to be list of objects
      val claims = HashMap(ALL_CLAIMS)
      claims["scope"] = listOf(
        object {
          val value = "read"
        },
        object {
          val value = "write"
        },
      )

      val testJWT = createTestJwt(
        jwtId = UUID.randomUUID().toString(),
        claims = claims,
      )

      whenever(authentication.accessToken)
        .thenReturn(OAuth2AccessToken(TokenType.BEARER, testJWT, issuedAt, expiresAt, SCOPE_RW))
      whenever(jwtDecoder.decode(testJWT)).thenReturn(jwt)
      whenever(jwt.claims).thenReturn(claims)

      tokenResponseHandler.onAuthenticationSuccess(request, response, authentication)

      assertTokenResponseContainsExpectedValues(
        testJWT,
      ) { additionalParams -> assertThat(additionalParams).doesNotContainKey("scope") }
    }
  }

  private fun assertTokenResponseContainsExpectedValues(
    expectedJWT: String,
    assertThatScopeClaimContainsExpectedValue: (additionalParameters: Map<String, Any>) -> Unit,
  ) {
    verify(oAuth2AccessTokenResponseHttpMessageConverter, times(1))
      .write(tokenResponseMessageConverterCaptor.capture(), isNull(), any())

    assertThat(tokenResponseMessageConverterCaptor.allValues).hasSize(1)

    val actual = tokenResponseMessageConverterCaptor.allValues[0]
    assertThat(actual).isNotNull

    assertThatScopeClaimContainsExpectedValue(actual.additionalParameters)

    assertThat(actual.accessToken.tokenValue).isEqualTo(expectedJWT)
    assertThat(actual.accessToken.tokenType).isEqualTo(TokenType.BEARER)
    assertThat(actual.accessToken.scopes).containsExactlyInAnyOrder("read", "write")
    assertThat(actual.accessToken.issuedAt).isCloseTo(issuedAt, within(1, SECONDS))
    assertThat(actual.accessToken.expiresAt).isCloseTo(expiresAt, within(1, SECONDS))
    assertThat(actual.additionalParameters["sub"]).isEqualTo("AUTH_MFA_PREF_EMAIL4")
    assertThat(actual.additionalParameters["jti"]).isEqualTo("OvQBycPwvHpv3MYEOtnrn6P55F0")
    assertThat(actual.additionalParameters["auth_source"]).isEqualTo("auth")
    assertThat(actual.additionalParameters["iss"]).isEqualTo("http://localhost/")
    assertThat(actual.additionalParameters["user_uuid"]).isEqualTo("2e285ccd-dcfd-4497-9e22-d6e8e10a2d63")
    assertThat(actual.additionalParameters["user_id"]).isEqualTo("3e285ccd-dcfd-4495-9e22-i6e8e10a2d63")
    assertThat(actual.additionalParameters["user_name"]).isEqualTo("AUTH_MFA_PREF_EMAIL4")
    assertThat(actual.additionalParameters["name"]).isEqualTo("Auth Mfa")
  }

  private fun createTestJwt(jwtId: String, claims: Map<String, Any>): String = Jwts.builder()
    .id(jwtId)
    .subject("AUTH_MFA_PREF_EMAIL4")
    .claims(claims)
    .signWith(
      SignatureAlgorithm.HS256,
      "ItsSupercalifragilisticexpialidociousEvenThoughTheSoundOfItIsSomethingQuiteAtrocious",
    ).compact()
}
