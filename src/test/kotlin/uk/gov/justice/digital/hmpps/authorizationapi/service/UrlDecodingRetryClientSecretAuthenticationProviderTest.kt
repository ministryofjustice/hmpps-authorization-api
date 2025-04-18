package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import java.lang.IllegalArgumentException
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

class UrlDecodingRetryClientSecretAuthenticationProviderTest {

  private val delegate: AuthenticationProvider = mock()

  private lateinit var urlDecodingRetryClientSecretAuthenticationProvider: UrlDecodingRetryClientSecretAuthenticationProvider

  @BeforeEach
  fun setUp() {
    urlDecodingRetryClientSecretAuthenticationProvider = UrlDecodingRetryClientSecretAuthenticationProvider(delegate)
  }

  @Test
  fun shouldDelegateAuthentication() {
    val authentication = givenAnAuthenticationWith("test-client-id:test-secret")
    whenever(delegate.authenticate(authentication)).thenReturn(authentication)

    val authenticated = urlDecodingRetryClientSecretAuthenticationProvider.authenticate(authentication)

    assertThat(authenticated).isEqualTo(authentication)
    verify(delegate).authenticate(authentication)
  }

  @Test
  fun shouldUrlDecodeCredentialsAndRetryOnAuthenticationException() {
    val originalSecret = "zK*AWM.,7QutO&hG(jp:L!&3DRyK13sjXR5aO(2x+kPjhCJ34wE&b*:mHn"
    val encodedSecret = URLEncoder.encode(originalSecret, StandardCharsets.UTF_8.toString())
    assertThat(encodedSecret).isNotEqualTo(originalSecret)
    val authenticationEncoded = givenAnAuthenticationWith("test-client-id:$encodedSecret")
    val authenticationDecoded = givenAnAuthenticationWith("test-client-id:$originalSecret")
    whenever(delegate.authenticate(authenticationEncoded)).thenThrow(OAuth2AuthenticationException("invalid secret"))
    whenever(delegate.authenticate(authenticationDecoded)).thenReturn(authenticationDecoded)

    val authenticated = urlDecodingRetryClientSecretAuthenticationProvider.authenticate(authenticationEncoded)

    assertThat(authenticated).isEqualTo(authenticationDecoded)
    verify(delegate, times(2)).authenticate(any())
  }

  @Test
  fun shouldUrlDecodeCredentialsOver72BytesAndRetryOnAuthenticationException() {
    val originalSecret = "zK*AWM.,7QutO&hG(jp:L!&3DRyK13sjXR5aO(2x+kPjhCJ34wE&b*:mHn"
    val encodedSecret = URLEncoder.encode(originalSecret, StandardCharsets.UTF_8.toString())
    assertThat(encodedSecret).isNotEqualTo(originalSecret)
    val authenticationEncoded = givenAnAuthenticationWith("test-client-id:$encodedSecret")
    val authenticationDecoded = givenAnAuthenticationWith("test-client-id:$originalSecret")
    whenever(delegate.authenticate(authenticationEncoded)).thenThrow(IllegalArgumentException("password cannot be more than 72 bytes"))
    whenever(delegate.authenticate(authenticationDecoded)).thenReturn(authenticationDecoded)

    val authenticated = urlDecodingRetryClientSecretAuthenticationProvider.authenticate(authenticationEncoded)

    assertThat(authenticated).isEqualTo(authenticationDecoded)
    verify(delegate, times(2)).authenticate(any())
  }

  private fun givenAnAuthenticationWith(credentials: String): Authentication = OAuth2ClientAuthenticationToken(
    "client-id",
    ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
    credentials,
    mapOf("this" to "that"),
  )
}
