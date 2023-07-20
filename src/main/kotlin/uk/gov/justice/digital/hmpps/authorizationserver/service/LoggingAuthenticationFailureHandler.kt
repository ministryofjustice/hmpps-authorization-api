package uk.gov.justice.digital.hmpps.authorizationserver.service

import com.microsoft.applicationinsights.TelemetryClient
import org.springframework.context.event.EventListener
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationserver.config.trackEvent
import uk.gov.justice.digital.hmpps.authorizationserver.utils.IpAddressHelper

@Component
class LoggingAuthenticationFailureHandler(
  private val telemetryClient: TelemetryClient,
  private val ipAddressHelper: IpAddressHelper,
) {

  @EventListener
  fun recordAuthenticationFailure(failure: OAuth2AuthenticationFailureEvent?) {
    failure?.let {
      val token = it.source
      if (token is OAuth2ClientAuthenticationToken) {
        telemetryClient.trackEvent(
          "CreateAccessTokenFailure",
          mapOf("clientId" to token.name, "clientIpAddress" to ipAddressHelper.retrieveIpFromRequest()),
        )
      }
    }
  }
}

class OAuth2AuthenticationFailureEvent(authentication: Authentication, exception: AuthenticationException) : AbstractAuthenticationFailureEvent(authentication, exception)
