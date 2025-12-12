package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.slf4j.LoggerFactory
import org.springframework.data.repository.findByIdOrNull
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationapi.security.AuthIpSecurity
import uk.gov.justice.digital.hmpps.authorizationapi.utils.IpAddressHelper
import java.time.LocalDate

class ClientCredentialsRequestValidator(
  private val delegate: AuthenticationProvider,
  private val clientConfigRepository: ClientConfigRepository,
  private val ipAddressHelper: IpAddressHelper,
  private val clientIdService: ClientIdService,
  private val authIpSecurity: AuthIpSecurity,
) : AuthenticationProvider {

  companion object {
    private val log = LoggerFactory.getLogger(this::class.java)
  }

  override fun authenticate(authentication: Authentication?): Authentication? {
    val clientCredentialsAuthentication = authentication as OAuth2ClientCredentialsAuthenticationToken

    if (clientCredentialsAuthentication.principal is OAuth2ClientAuthenticationToken) {
      val clientId = (clientCredentialsAuthentication.principal as OAuth2ClientAuthenticationToken).registeredClient?.clientId
      val baseClientId = clientIdService.toBase(clientId!!)
      val clientConfig = clientConfigRepository.findByIdOrNull(baseClientId)
      val clientIpAddress = ipAddressHelper.retrieveIpFromRequest()

      if (clientConfig?.clientEndDate != null && clientConfig.clientEndDate!!.isBefore(LocalDate.now())) {
        log.warn("Client id $baseClientId has expired")
        throw ClientExpiredException(clientConfig.baseClientId)
      }

      if (!clientConfig?.ips.isNullOrEmpty()) {
        authIpSecurity.validateClientIpAllowed(clientIpAddress, clientConfig.ips, clientId)
      }

      return delegate.authenticate(authentication)
    }

    return null
  }

  override fun supports(authentication: Class<*>): Boolean = OAuth2ClientCredentialsAuthenticationToken::class.java.isAssignableFrom(authentication)
}

class IPAddressNotAllowedException : AuthenticationException("Unable to issue token as request is not from ip within allowed list")

class ClientExpiredException(clientId: String) : AuthenticationException("Client $clientId has expired")
