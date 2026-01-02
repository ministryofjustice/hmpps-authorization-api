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
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient

class ClientCredentialsTokenRequestValidatorTest {
  private val delegate: AuthenticationProvider = mock()
  private val oAuthClientRequestValidator: OAuthClientRequestValidator = mock()

  private val clientCredentialsRequestValidator = ClientCredentialsTokenRequestValidator(delegate, oAuthClientRequestValidator)

  private val clientId = "testy_mc_tester"
  private lateinit var authenticationToken: OAuth2ClientCredentialsAuthenticationToken

  @BeforeEach
  fun setUp() {
    authenticationToken = givenAToken()
  }

  @Test
  fun shouldFailWhenRequestFailsValidationDueToIPRestriction() {
    doThrow(IPAddressNotAllowedException::class).whenever(oAuthClientRequestValidator).validateRequestByClientId(clientId)

    assertThatThrownBy {
      clientCredentialsRequestValidator.authenticate(authenticationToken)
    }.isInstanceOf(IPAddressNotAllowedException::class.java)

    verify(delegate, never()).authenticate(authenticationToken)
  }

  @Test
  fun shouldFailWhenRequestFailsValidationDueToClientExpiry() {
    doThrow(ClientExpiredException::class).whenever(oAuthClientRequestValidator).validateRequestByClientId(clientId)

    assertThatThrownBy {
      clientCredentialsRequestValidator.authenticate(authenticationToken)
    }.isInstanceOf(ClientExpiredException::class.java)

    verify(delegate, never()).authenticate(authenticationToken)
  }

  @Test
  fun shouldDelegateWhenPassesValidation() {
    clientCredentialsRequestValidator.authenticate(authenticationToken)
    verify(delegate).authenticate(authenticationToken)
  }

  private fun givenAToken(): OAuth2ClientCredentialsAuthenticationToken {
    val registeredClient = RegisteredClient.withId("1234")
      .clientId(clientId)
      .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
      .build()

    val oAuth2ClientAuthenticationToken =
      OAuth2ClientAuthenticationToken(registeredClient, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null)
    return OAuth2ClientCredentialsAuthenticationToken(oAuth2ClientAuthenticationToken, null, null)
  }
}
