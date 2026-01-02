package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.doThrow
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient

class AuthorisationCodeTokenRequestValidatorTest {
  private val delegate: AuthenticationProvider = mock()
  private val oAuthClientRequestValidator: OAuthClientRequestValidator = mock()

  private val authorisationCodeTokenRequestValidator = AuthorisationCodeTokenRequestValidator(delegate, oAuthClientRequestValidator)

  private val clientId = "testy_mc_tester"
  private lateinit var authenticationToken: OAuth2AuthorizationCodeAuthenticationToken

  @BeforeEach
  fun setUp() {
    authenticationToken = givenAToken()
  }

  @Test
  fun shouldFailWhenRequestFailsValidationDueToIPRestriction() {
    doThrow(IPAddressNotAllowedException::class).whenever(oAuthClientRequestValidator).validateRequestByClientId(clientId)

    assertThatThrownBy {
      authorisationCodeTokenRequestValidator.authenticate(authenticationToken)
    }.isInstanceOf(IPAddressNotAllowedException::class.java)

    verify(delegate, never()).authenticate(authenticationToken)
  }

  @Test
  fun shouldFailWhenRequestFailsValidationDueToClientExpiry() {
    doThrow(ClientExpiredException::class).whenever(oAuthClientRequestValidator).validateRequestByClientId(clientId)

    assertThatThrownBy {
      authorisationCodeTokenRequestValidator.authenticate(authenticationToken)
    }.isInstanceOf(ClientExpiredException::class.java)

    verify(delegate, never()).authenticate(authenticationToken)
  }

  @Test
  fun shouldDelegateWhenPassesValidation() {
    authorisationCodeTokenRequestValidator.authenticate(authenticationToken)
    verify(delegate).authenticate(authenticationToken)
  }

  private fun givenAToken(): OAuth2AuthorizationCodeAuthenticationToken {
    val registeredClient = RegisteredClient.withId("1234")
      .clientId(clientId)
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .redirectUri("http://localhost/authorisationCode")
      .build()

    val oAuth2ClientAuthenticationToken =
      OAuth2ClientAuthenticationToken(registeredClient, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null)
    return OAuth2AuthorizationCodeAuthenticationToken("1234", oAuth2ClientAuthenticationToken, null, null)
  }
}
