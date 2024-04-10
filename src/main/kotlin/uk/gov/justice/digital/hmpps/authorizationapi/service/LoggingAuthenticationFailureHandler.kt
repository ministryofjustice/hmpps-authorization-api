package uk.gov.justice.digital.hmpps.authorizationapi.service

import com.microsoft.applicationinsights.TelemetryClient
import org.springframework.context.event.EventListener
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent
import org.springframework.security.authentication.event.AuthenticationFailureCredentialsExpiredEvent
import org.springframework.security.authentication.event.AuthenticationFailureDisabledEvent
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent
import org.springframework.security.authentication.event.AuthenticationFailureProxyUntrustedEvent
import org.springframework.security.authentication.event.AuthenticationFailureServiceExceptionEvent
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationapi.config.trackEvent
import uk.gov.justice.digital.hmpps.authorizationapi.utils.IpAddressHelper

@Component
class LoggingAuthenticationFailureHandler(
  private val telemetryClient: TelemetryClient,
  private val ipAddressHelper: IpAddressHelper,
) {

  @EventListener
  fun recordAuthenticationProxyUntrustedFailure(failure: AuthenticationFailureProxyUntrustedEvent?) {
    recordEvent("AuthorizationApiProxyUntrustedFailure", failure)
  }

  @EventListener
  fun recordAuthenticationCredentialsExpiredFailure(failure: AuthenticationFailureCredentialsExpiredEvent?) {
    recordEvent("AuthorizationApiCredentialsExpiredFailure", failure)
  }

  @EventListener
  fun recordAuthenticationServiceExceptionFailure(failure: AuthenticationFailureServiceExceptionEvent?) {
    recordEvent("AuthorizationApiServiceExceptionFailure", failure)
  }

  @EventListener
  fun recordAuthenticationLockedFailure(failure: AuthenticationFailureLockedEvent?) {
    recordEvent("AuthorizationApiLockedFailure", failure)
  }

  @EventListener
  fun recordDisabledFailure(failure: AuthenticationFailureDisabledEvent?) {
    recordEvent("AuthorizationApiDisabledFailure", failure)
  }

  @EventListener
  fun recordBadCredentialsFailure(failure: AuthenticationFailureBadCredentialsEvent?) {
    recordEvent("AuthorizationApiBadCredentialsFailure", failure)
  }

  @EventListener
  fun recordAuthenticationFailure(failure: OAuth2AuthenticationFailureEvent?) {
    recordEvent("AuthorizationApiCreateAccessTokenFailure", failure)
  }

  private fun recordEvent(eventName: String, failure: AbstractAuthenticationFailureEvent?) {
    failure?.let {
      val token = it.source
      if (token is AbstractAuthenticationToken) {
        telemetryClient.trackEvent(
          eventName,
          mapOf("clientId" to token.name, "clientIpAddress" to ipAddressHelper.retrieveIpFromRequest()),
        )
      }
    }
  }
}

class OAuth2AuthenticationFailureEvent(authentication: Authentication, exception: AuthenticationException) : AbstractAuthenticationFailureEvent(authentication, exception)
