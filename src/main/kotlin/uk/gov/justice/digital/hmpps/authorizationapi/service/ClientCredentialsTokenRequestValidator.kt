package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken

class ClientCredentialsTokenRequestValidator(
  private val delegate: AuthenticationProvider,
  private val oAuthClientRequestValidator: OAuthClientRequestValidator,
) : AuthenticationProvider {

  override fun authenticate(authentication: Authentication?): Authentication? {
    val clientCredentialsAuthentication = authentication as OAuth2ClientCredentialsAuthenticationToken

    if (clientCredentialsAuthentication.principal is OAuth2ClientAuthenticationToken) {
      val clientId = (clientCredentialsAuthentication.principal as OAuth2ClientAuthenticationToken).registeredClient?.clientId
      oAuthClientRequestValidator.validateRequestByClientId(clientId)
      return delegate.authenticate(authentication)
    }

    return null
  }

  override fun supports(authentication: Class<*>): Boolean = OAuth2ClientCredentialsAuthenticationToken::class.java.isAssignableFrom(authentication)
}

class IPAddressNotAllowedException : AuthenticationException("Unable to issue token as request is not from ip within allowed list")

class ClientExpiredException(clientId: String) : AuthenticationException("Client $clientId has expired")
