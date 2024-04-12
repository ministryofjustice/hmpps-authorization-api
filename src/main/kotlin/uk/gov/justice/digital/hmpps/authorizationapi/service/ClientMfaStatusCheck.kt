package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken

class ClientMfaStatusCheck(
  private val delegate: AuthenticationProvider,
) : AuthenticationProvider {

  override fun authenticate(authentication: Authentication?): Authentication {
    val authorizationCodeRequestAuthentication = authentication as OAuth2AuthorizationCodeRequestAuthenticationToken

    return delegate.authenticate(authentication)
  }

  override fun supports(authentication: Class<*>?): Boolean {
    return OAuth2AuthorizationCodeRequestAuthenticationToken::class.java.isAssignableFrom(authentication!!)
  }
}
