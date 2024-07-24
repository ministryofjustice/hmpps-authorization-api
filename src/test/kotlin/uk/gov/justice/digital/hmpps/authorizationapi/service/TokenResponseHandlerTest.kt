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
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import java.time.Instant
import java.time.temporal.ChronoUnit.SECONDS
import java.util.UUID

@ExtendWith(MockitoExtension::class)
class TokenResponseHandlerTest {

  @Mock
  private lateinit var oAuth2AccessTokenResponseHttpMessageConverter: OAuth2AccessTokenResponseHttpMessageConverter

  @Mock
  private lateinit var request: HttpServletRequest

  @Mock
  private lateinit var response: HttpServletResponse

  @Mock
  private lateinit var authentication: OAuth2AccessTokenAuthenticationToken

  private lateinit var tokenResponseHandler: TokenResponseHandler

  private lateinit var issuedAt: Instant

  private lateinit var expiresAt: Instant

  @Captor
  private lateinit var tokenResponseMessageConverterCaptor: ArgumentCaptor<OAuth2AccessTokenResponse>

  companion object {
    const val USERNAME = "AUTH_MFA_PREF_EMAIL4"
    const val SUBJECT = "AUTH_MFA_PREF_EMAIL4" // Subject intentionally set to user_name value
    const val AUTH_SOURCE = "auth"
    const val ISSUER = "http://localhost:51315/auth/issuer"
    const val CLIENT_ID = "some-client-id"
    const val USER_ID = "2e285ccd-dcfd-4497-9e22-d6e8e10a2d63"
    const val USER_UUID = "3e285ccd-dcfd-4495-9e22-i6e8e10a2d63"
    const val GRANT_TYPE_AUTH_CODE = "authorization_code"
    const val NAME = "Auth Mfa"
    const val EXPIRY = 1721752178
    const val JTI = "OvQBycPwvHpv3MYEOtnrn6P55F0"

    val SCOPE_RW = setOf("read", "write")
    val AUTHORITIES = listOf("ROLE_MFA")

    val ALL_CLAIMS = mapOf(
      "sub" to SUBJECT,
      "user_name" to USERNAME,
      "auth_source" to AUTH_SOURCE,
      "iss" to ISSUER,
      "authorities" to AUTHORITIES,
      "client_id" to CLIENT_ID,
      "user_uuid" to USER_UUID,
      "grant_type" to GRANT_TYPE_AUTH_CODE,
      "user_id" to USER_ID,
      "scope" to SCOPE_RW,
      "name" to NAME,
      "exp" to EXPIRY,
      "jti" to JTI,
    )
  }

  @BeforeEach
  fun setup() {
    issuedAt = Instant.now()
    expiresAt = issuedAt.plusSeconds(3600)

    tokenResponseHandler = TokenResponseHandler(oAuth2AccessTokenResponseHttpMessageConverter)
  }

  @Test
  fun `TokenResponseHandler adds the expected additional properties to the token response`() {
    val testJWT = createTestJwt(
      jwtId = UUID.randomUUID().toString(),
      subject = SUBJECT,
      claims = ALL_CLAIMS,
    )

    whenever(authentication.accessToken)
      .thenReturn(OAuth2AccessToken(TokenType.BEARER, testJWT, issuedAt, expiresAt, SCOPE_RW))

    tokenResponseHandler.onAuthenticationSuccess(request, response, authentication)

    verify(oAuth2AccessTokenResponseHttpMessageConverter, times(1))
      .write(tokenResponseMessageConverterCaptor.capture(), isNull(), any())

    assertThat(tokenResponseMessageConverterCaptor.allValues).hasSize(1)

    val capturedAccessToken = tokenResponseMessageConverterCaptor.allValues[0]
    assertThat(capturedAccessToken).isNotNull

    assertThat(capturedAccessToken.accessToken.tokenValue).isEqualTo(testJWT)
    assertThat(capturedAccessToken.accessToken.tokenType).isEqualTo(TokenType.BEARER)
    assertThat(capturedAccessToken.accessToken.scopes).containsExactlyInAnyOrder("read", "write")
    assertThat(capturedAccessToken.accessToken.issuedAt).isCloseTo(issuedAt, within(1, SECONDS))
    assertThat(capturedAccessToken.accessToken.expiresAt).isCloseTo(expiresAt, within(1, SECONDS))
    assertThat(capturedAccessToken.additionalParameters["sub"]).isEqualTo(SUBJECT)
    assertThat(capturedAccessToken.additionalParameters["jti"]).isEqualTo(JTI)
    assertThat(capturedAccessToken.additionalParameters["auth_source"]).isEqualTo(AUTH_SOURCE)
    assertThat(capturedAccessToken.additionalParameters["iss"]).isEqualTo(ISSUER)
    assertThat(capturedAccessToken.additionalParameters["user_uuid"]).isEqualTo(USER_UUID)
    assertThat(capturedAccessToken.additionalParameters["user_id"]).isEqualTo(USER_ID)
    assertThat(capturedAccessToken.additionalParameters["user_name"]).isEqualTo(USERNAME)
    assertThat(capturedAccessToken.additionalParameters["scope"]).isEqualTo("read write")
    assertThat(capturedAccessToken.additionalParameters["name"]).isEqualTo(NAME)
  }

  @Nested
  inner class ScopeClaim {
    @Test
    fun `additional property scope is not added when it does not exist is in the source access token`() {
      // Remove scope from the claims
      val claims = HashMap(ALL_CLAIMS)
      claims.remove("scope")

      val testJWT = createTestJwt(
        jwtId = UUID.randomUUID().toString(),
        subject = SUBJECT,
        claims = claims,
      )

      whenever(authentication.accessToken)
        .thenReturn(OAuth2AccessToken(TokenType.BEARER, testJWT, issuedAt, expiresAt, SCOPE_RW))

      tokenResponseHandler.onAuthenticationSuccess(request, response, authentication)

      verify(oAuth2AccessTokenResponseHttpMessageConverter, times(1))
        .write(tokenResponseMessageConverterCaptor.capture(), isNull(), any())

      assertThat(tokenResponseMessageConverterCaptor.allValues).hasSize(1)

      val capturedAccessToken = tokenResponseMessageConverterCaptor.allValues[0]
      assertThat(capturedAccessToken).isNotNull

      assertThat(capturedAccessToken.additionalParameters).doesNotContainKey("scope")

      assertThat(capturedAccessToken.accessToken.tokenValue).isEqualTo(testJWT)
      assertThat(capturedAccessToken.accessToken.tokenType).isEqualTo(TokenType.BEARER)
      assertThat(capturedAccessToken.accessToken.scopes).containsExactlyInAnyOrder("read", "write")
      assertThat(capturedAccessToken.accessToken.issuedAt).isCloseTo(issuedAt, within(1, SECONDS))
      assertThat(capturedAccessToken.accessToken.expiresAt).isCloseTo(expiresAt, within(1, SECONDS))
      assertThat(capturedAccessToken.additionalParameters["sub"]).isEqualTo(SUBJECT)
      assertThat(capturedAccessToken.additionalParameters["jti"]).isEqualTo(JTI)
      assertThat(capturedAccessToken.additionalParameters["auth_source"]).isEqualTo(AUTH_SOURCE)
      assertThat(capturedAccessToken.additionalParameters["iss"]).isEqualTo(ISSUER)
      assertThat(capturedAccessToken.additionalParameters["user_uuid"]).isEqualTo(USER_UUID)
      assertThat(capturedAccessToken.additionalParameters["user_id"]).isEqualTo(USER_ID)
      assertThat(capturedAccessToken.additionalParameters["user_name"]).isEqualTo(USERNAME)
      assertThat(capturedAccessToken.additionalParameters["name"]).isEqualTo(NAME)
    }

    @Test
    fun `additional property scope is not added when scope is present with a null value in the source access token`() {
      // Update scope to have null value
      val claims = HashMap(ALL_CLAIMS)
      claims["scope"] = null

      val testJWT = createTestJwt(
        jwtId = UUID.randomUUID().toString(),
        subject = SUBJECT,
        claims = claims,
      )

      whenever(authentication.accessToken)
        .thenReturn(OAuth2AccessToken(TokenType.BEARER, testJWT, issuedAt, expiresAt, SCOPE_RW))

      tokenResponseHandler.onAuthenticationSuccess(request, response, authentication)

      verify(oAuth2AccessTokenResponseHttpMessageConverter, times(1))
        .write(tokenResponseMessageConverterCaptor.capture(), isNull(), any())

      assertThat(tokenResponseMessageConverterCaptor.allValues).hasSize(1)

      val capturedAccessToken = tokenResponseMessageConverterCaptor.allValues[0]
      assertThat(capturedAccessToken).isNotNull

      assertThat(capturedAccessToken.additionalParameters).doesNotContainKey("scope")

      assertThat(capturedAccessToken.accessToken.tokenValue).isEqualTo(testJWT)
      assertThat(capturedAccessToken.accessToken.tokenType).isEqualTo(TokenType.BEARER)
      assertThat(capturedAccessToken.accessToken.scopes).containsExactlyInAnyOrder("read", "write")
      assertThat(capturedAccessToken.accessToken.issuedAt).isCloseTo(issuedAt, within(1, SECONDS))
      assertThat(capturedAccessToken.accessToken.expiresAt).isCloseTo(expiresAt, within(1, SECONDS))
      assertThat(capturedAccessToken.additionalParameters["sub"]).isEqualTo(SUBJECT)
      assertThat(capturedAccessToken.additionalParameters["jti"]).isEqualTo(JTI)
      assertThat(capturedAccessToken.additionalParameters["auth_source"]).isEqualTo(AUTH_SOURCE)
      assertThat(capturedAccessToken.additionalParameters["iss"]).isEqualTo(ISSUER)
      assertThat(capturedAccessToken.additionalParameters["user_uuid"]).isEqualTo(USER_UUID)
      assertThat(capturedAccessToken.additionalParameters["user_id"]).isEqualTo(USER_ID)
      assertThat(capturedAccessToken.additionalParameters["user_name"]).isEqualTo(USERNAME)
      assertThat(capturedAccessToken.additionalParameters["name"]).isEqualTo(NAME)
    }

    @Test
    fun `additional property scope is empty when scope is present with empty value in the source access token`() {
      // Update scope to have empty value
      val claims = HashMap(ALL_CLAIMS)
      claims["scope"] = emptyList<String>()

      val testJWT = createTestJwt(
        jwtId = UUID.randomUUID().toString(),
        subject = SUBJECT,
        claims = claims,
      )

      whenever(authentication.accessToken)
        .thenReturn(OAuth2AccessToken(TokenType.BEARER, testJWT, issuedAt, expiresAt, SCOPE_RW))

      tokenResponseHandler.onAuthenticationSuccess(request, response, authentication)

      verify(oAuth2AccessTokenResponseHttpMessageConverter, times(1))
        .write(tokenResponseMessageConverterCaptor.capture(), isNull(), any())

      assertThat(tokenResponseMessageConverterCaptor.allValues).hasSize(1)

      val capturedAccessToken = tokenResponseMessageConverterCaptor.allValues[0]
      assertThat(capturedAccessToken).isNotNull

      assertThat(capturedAccessToken.additionalParameters["scope"]).isEqualTo("")

      assertThat(capturedAccessToken.accessToken.tokenValue).isEqualTo(testJWT)
      assertThat(capturedAccessToken.accessToken.tokenType).isEqualTo(TokenType.BEARER)
      assertThat(capturedAccessToken.accessToken.scopes).containsExactlyInAnyOrder("read", "write")
      assertThat(capturedAccessToken.accessToken.issuedAt).isCloseTo(issuedAt, within(1, SECONDS))
      assertThat(capturedAccessToken.accessToken.expiresAt).isCloseTo(expiresAt, within(1, SECONDS))
      assertThat(capturedAccessToken.additionalParameters["sub"]).isEqualTo(SUBJECT)
      assertThat(capturedAccessToken.additionalParameters["jti"]).isEqualTo(JTI)
      assertThat(capturedAccessToken.additionalParameters["auth_source"]).isEqualTo(AUTH_SOURCE)
      assertThat(capturedAccessToken.additionalParameters["iss"]).isEqualTo(ISSUER)
      assertThat(capturedAccessToken.additionalParameters["user_uuid"]).isEqualTo(USER_UUID)
      assertThat(capturedAccessToken.additionalParameters["user_id"]).isEqualTo(USER_ID)
      assertThat(capturedAccessToken.additionalParameters["user_name"]).isEqualTo(USERNAME)
      assertThat(capturedAccessToken.additionalParameters["name"]).isEqualTo(NAME)
    }
  }

  internal fun createTestJwt(jwtId: String, subject: String, claims: Map<String, Any>): String {
    return Jwts.builder()
      .id(jwtId)
      .subject(subject)
      .claims(claims)
      .signWith(
        SignatureAlgorithm.HS256,
        "ItsSupercalifragilisticexpialidociousEvenThoughTheSoundOfItIsSomethingQuiteAtrocious",
      ).compact()
  }
}
