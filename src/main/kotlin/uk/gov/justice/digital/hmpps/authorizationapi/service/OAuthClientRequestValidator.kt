package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.slf4j.LoggerFactory
import org.springframework.data.repository.findByIdOrNull
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationapi.security.AuthIpSecurity
import uk.gov.justice.digital.hmpps.authorizationapi.utils.IpAddressHelper
import java.time.LocalDate

class OAuthClientRequestValidator(
  private val clientIdService: ClientIdService,
  private val clientConfigRepository: ClientConfigRepository,
  private val ipAddressHelper: IpAddressHelper,
  private val authIpSecurity: AuthIpSecurity,
) {
  companion object {
    private val log = LoggerFactory.getLogger(this::class.java)
  }

  fun validateRequestByClientId(clientId: String?) {
    val baseClientId = clientIdService.toBase(clientId!!)
    val clientConfig = clientConfigRepository.findByIdOrNull(baseClientId)
    val clientIpAddress = ipAddressHelper.retrieveIpFromRequest()

    if (clientConfig?.clientEndDate != null && clientConfig.clientEndDate!!.isBefore(LocalDate.now())) {
      log.warn("Client id $baseClientId has expired")
      throw ClientExpiredException(clientConfig.baseClientId)
    }

    authIpSecurity.validateCallReceivedFromPermittedIPAddress(clientIpAddress, clientId)
  }
}
