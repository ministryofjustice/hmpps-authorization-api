package uk.gov.justice.digital.hmpps.authorizationserver.service

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationToken

class OidcClientRegistrationDataHandler(
  private val delegate: AuthenticationProvider,
) : AuthenticationProvider {

  override fun authenticate(authentication: Authentication?): Authentication {
    val clientRegistrationAuthentication = authentication as OidcClientRegistrationAuthenticationToken

    val authenticationResult = delegate.authenticate(authentication).let {
      val claims = clientRegistrationAuthentication.clientRegistration.claims

      // TODO extract data from claims and store

      return@let it
    }

    return authenticationResult
  }

  override fun supports(authentication: Class<*>): Boolean {
    return OidcClientRegistrationAuthenticationToken::class.java.isAssignableFrom(authentication)
  }
}
