package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.assertj.core.api.Assertions.assertThatCode
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock
import org.mockito.kotlin.doThrow
import org.mockito.kotlin.whenever
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.ClientConfig
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationapi.security.AuthIpSecurity
import uk.gov.justice.digital.hmpps.authorizationapi.utils.IpAddressHelper
import java.time.LocalDate
import java.util.Optional

class OAuthClientRequestValidatorTest {
  private val clientIdService: ClientIdService = mock()
  private val clientConfigRepository: ClientConfigRepository = mock()
  private val ipAddressHelper: IpAddressHelper = mock()
  private val authIpSecurity: AuthIpSecurity = mock()

  private lateinit var oAuthClientRequestValidator: OAuthClientRequestValidator
  private val clientId = "testy_mc_tester"

  @BeforeEach
  fun setup() {
    oAuthClientRequestValidator = OAuthClientRequestValidator(clientIdService, clientConfigRepository, ipAddressHelper, authIpSecurity)
    whenever(clientIdService.toBase(clientId)).thenReturn(clientId)
  }

  @Test
  fun shouldNotFailWhenClientConfigAbsent() {
    whenever(clientConfigRepository.findById(clientId)).thenReturn(Optional.empty())

    assertThatCode {
      oAuthClientRequestValidator.validateRequestByClientId(clientId)
    }.doesNotThrowAnyException()
  }

  @Test
  fun shouldNotFailWhenClientConfigHasNoConfiguredEndDate() {
    whenever(clientConfigRepository.findById(clientId)).thenReturn(Optional.of(givenAClientConfig(null)))

    assertThatCode {
      oAuthClientRequestValidator.validateRequestByClientId(clientId)
    }.doesNotThrowAnyException()
  }

  @Test
  fun shouldFailWhenClientConfigExpired() {
    whenever(clientConfigRepository.findById(clientId)).thenReturn(Optional.of(givenAClientConfig(LocalDate.now().minusDays(2))))

    assertThatThrownBy {
      oAuthClientRequestValidator.validateRequestByClientId(clientId)
    }.isInstanceOf(ClientExpiredException::class.java)
  }

  @Test
  fun shouldFailWhenClientIPNotPermitted() {
    whenever(ipAddressHelper.retrieveIpFromRequest()).thenReturn("1.2.3.4")
    whenever(clientConfigRepository.findById(clientId)).thenReturn(Optional.of(givenAClientConfig(LocalDate.now().plusDays(2), "1.2.3.5")))
    doThrow(IPAddressNotAllowedException()).whenever(authIpSecurity).validateCallReceivedFromPermittedIPAddress("1.2.3.4", clientId)

    assertThatThrownBy {
      oAuthClientRequestValidator.validateRequestByClientId(clientId)
    }.isInstanceOf(IPAddressNotAllowedException::class.java)
  }

  private fun givenAClientConfig(expiryDate: LocalDate?, vararg allowedIPs: String): ClientConfig = ClientConfig(clientId, allowedIPs.asList(), expiryDate)
}
