package uk.gov.justice.digital.hmpps.authorizationserver.service

import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientConfig
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationserver.utils.IpAddressHelper
import java.util.Optional

class ClientCredentialsIpAddressValidatorTest {
  private val delegate: AuthenticationProvider = mock()
  private val clientConfigRepository: ClientConfigRepository = mock()
  private val ipAddressHelper: IpAddressHelper = mock()

  private val clientCredentialsIpAddressValidator = ClientCredentialsIpAddressValidator(delegate, clientConfigRepository, ipAddressHelper)

  @Test
  fun shouldNotValidateClientIPWhenClientConfigNotPresent() {
    val clientId = "testy_mc_tester"
    val authenticationToken = givenAToken(clientId)
    whenever(clientConfigRepository.findById(clientId)).thenReturn(Optional.empty())
    whenever(ipAddressHelper.retrieveIpFromRequest()).thenReturn("1.2.3.4")
    whenever(delegate.authenticate(authenticationToken)).thenReturn(authenticationToken)

    clientCredentialsIpAddressValidator.authenticate(authenticationToken)

    verify(delegate).authenticate(authenticationToken)
  }

  @Test
  fun shouldNotValidateClientIPWhenClientConfigPresentButContainsNoAllowedIPAddresses() {
    val clientId = "testy_mc_tester"
    val authenticationToken = givenAToken(clientId)
    whenever(clientConfigRepository.findById(clientId)).thenReturn(Optional.of(givenAClientConfig(clientId)))
    whenever(ipAddressHelper.retrieveIpFromRequest()).thenReturn("1.2.3.4")
    whenever(delegate.authenticate(authenticationToken)).thenReturn(authenticationToken)

    clientCredentialsIpAddressValidator.authenticate(authenticationToken)

    verify(delegate).authenticate(authenticationToken)
  }

  @Test
  fun shouldFailWhenClientConfigExpired() {
  }

  @Test
  fun shouldFailWhenClientIPNotPresentInClientConfig() {
  }

  @Test
  fun shouldDelegateWhenClientIPIsAllowed() {
  }

  private fun givenAClientConfig(clientId: String, vararg allowedIPs: String): ClientConfig {
    return ClientConfig(clientId, allowedIPs.asList())
  }

  private fun givenAToken(clientId: String): OAuth2ClientCredentialsAuthenticationToken {
    val registeredClient = RegisteredClient.withId("1234")
      .clientId(clientId)
      .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
      .build()

    val oAuth2ClientAuthenticationToken =
      OAuth2ClientAuthenticationToken(registeredClient, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null)
    return OAuth2ClientCredentialsAuthenticationToken(oAuth2ClientAuthenticationToken, null, null)
  }
}
