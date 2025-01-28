package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.anyString
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
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.ClientConfig
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientConfigRepository
import java.time.LocalDate
import java.util.Optional

class ClientCredentialsRequestValidatorTest {
  private val delegate: AuthenticationProvider = mock()
  private val clientConfigRepository: ClientConfigRepository = mock()
  private val clientIdService: ClientIdService = mock()

  private val clientCredentialsRequestValidator = ClientCredentialsRequestValidator(delegate, clientConfigRepository, clientIdService)

  private val clientId = "testy_mc_tester"
  private lateinit var authenticationToken: OAuth2ClientCredentialsAuthenticationToken

  @BeforeEach
  fun setUp() {
    whenever(clientIdService.toBase(anyString())).thenReturn(clientId)
    authenticationToken = givenAToken()
  }

  @Test
  fun shouldNotFailWhenClientConfigAbsent() {
    whenever(clientConfigRepository.findById(clientId)).thenReturn(Optional.empty())
    whenever(delegate.authenticate(authenticationToken)).thenReturn(authenticationToken)

    assertNotNull(clientCredentialsRequestValidator.authenticate(authenticationToken))

    verify(delegate).authenticate(authenticationToken)
  }

  @Test
  fun shouldNotFailWhenClientConfigHasNoConfiguredEndDate() {
    whenever(clientConfigRepository.findById(clientId)).thenReturn(Optional.of(givenAClientConfig(null)))
    whenever(delegate.authenticate(authenticationToken)).thenReturn(authenticationToken)

    assertNotNull(clientCredentialsRequestValidator.authenticate(authenticationToken))

    verify(delegate).authenticate(authenticationToken)
  }

  @Test
  fun shouldFailWhenClientConfigExpired() {
    whenever(clientConfigRepository.findById(clientId)).thenReturn(Optional.of(givenAClientConfig(LocalDate.now().minusDays(2))))

    assertThatThrownBy {
      clientCredentialsRequestValidator.authenticate(authenticationToken)
    }.isInstanceOf(ClientExpiredException::class.java)

    verify(delegate, never()).authenticate(authenticationToken)
  }

  private fun givenAClientConfig(expiryDate: LocalDate?, vararg allowedIPs: String): ClientConfig = ClientConfig(clientId, allowedIPs.asList(), expiryDate)

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
