package uk.gov.justice.digital.hmpps.authorizationserver.service

import org.slf4j.LoggerFactory
import org.springframework.data.repository.findByIdOrNull
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken
import org.springframework.security.web.util.matcher.IpAddressMatcher
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientConfig.Companion.baseClientId
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationserver.utils.IpAddressHelper
import java.time.LocalDate

class ClientCredentialsRequestValidator(
  private val delegate: AuthenticationProvider,
  private val clientConfigRepository: ClientConfigRepository,
  private val ipAddressHelper: IpAddressHelper,
) : AuthenticationProvider {

  companion object {
    private val log = LoggerFactory.getLogger(this::class.java)
  }

  override fun authenticate(authentication: Authentication?): Authentication {
    val clientCredentialsAuthentication = authentication as OAuth2ClientCredentialsAuthenticationToken
    val clientId = (clientCredentialsAuthentication.principal as OAuth2ClientAuthenticationToken).registeredClient?.clientId
    val baseClientId = baseClientId(clientId!!)
    val clientConfig = clientConfigRepository.findByIdOrNull(baseClientId)
    val clientIpAddress = ipAddressHelper.retrieveIpFromRequest()

    if (clientConfig?.clientEndDate != null && clientConfig.clientEndDate!!.isBefore(LocalDate.now())) {
      log.warn("Client id $baseClientId has expired")
      throw ClientExpiredException(clientConfig.baseClientId)
    }

    if (!clientConfig?.ips.isNullOrEmpty()) {
      validateClientIpAllowed(clientIpAddress, clientConfig?.ips!!)
    }

    return delegate.authenticate(authentication)
  }

  override fun supports(authentication: Class<*>?): Boolean {
    return OAuth2ClientCredentialsAuthenticationToken::class.java.isAssignableFrom(authentication!!)
  }

  private fun validateClientIpAllowed(remoteIp: String?, clientAllowList: List<String>) {
    val matchIp = clientAllowList.any { ip: String? -> IpAddressMatcher(ip).matches(remoteIp) }
    if (!matchIp) {
      log.warn("Client IP: $remoteIp not in client allowlist: $clientAllowList")
      throw IPAddressNotAllowedException(remoteIp)
    }
  }
}

class IPAddressNotAllowedException(remoteIp: String?) : AuthenticationException("Remote IP address $remoteIp not in client allow list")

class ClientExpiredException(clientId: String) : AuthenticationException("Client $clientId has expired")
