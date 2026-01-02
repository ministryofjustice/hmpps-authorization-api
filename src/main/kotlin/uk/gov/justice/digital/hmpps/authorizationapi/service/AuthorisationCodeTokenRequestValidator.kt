package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken

class AuthorisationCodeTokenRequestValidator(
  private val delegate: AuthenticationProvider,
  private val oAuthClientRequestValidator: OAuthClientRequestValidator,
) : AuthenticationProvider {

  override fun authenticate(authentication: Authentication?): Authentication? {
    val authorisationCodeAuthentication = authentication as OAuth2AuthorizationCodeAuthenticationToken

    if (authorisationCodeAuthentication.principal is OAuth2ClientAuthenticationToken) {
      val clientId = (authorisationCodeAuthentication.principal as OAuth2ClientAuthenticationToken).registeredClient?.clientId
      oAuthClientRequestValidator.validateRequestByClientId(clientId)
      return delegate.authenticate(authentication)
    }

    return null
  }

  override fun supports(authentication: Class<*>): Boolean = OAuth2AuthorizationCodeAuthenticationToken::class.java.isAssignableFrom(authentication)
}
