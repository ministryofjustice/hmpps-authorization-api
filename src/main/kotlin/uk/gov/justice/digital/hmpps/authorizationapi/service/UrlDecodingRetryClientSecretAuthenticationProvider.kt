package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

class UrlDecodingRetryClientSecretAuthenticationProvider(
  private val delegate: AuthenticationProvider,
) : AuthenticationProvider {

  override fun authenticate(authentication: Authentication?): Authentication? = try {
    delegate.authenticate(authentication)
  } catch (e: OAuth2AuthenticationException) {
    authentication?.credentials?.let {
      val urlDecodedCredentials = decodeCredentials(it.toString())

      val clientAuthentication = authentication as OAuth2ClientAuthenticationToken
      val decodedAuthentication = OAuth2ClientAuthenticationToken(
        clientAuthentication.principal.toString(),
        clientAuthentication.clientAuthenticationMethod,
        urlDecodedCredentials,
        clientAuthentication.additionalParameters,
      )

      delegate.authenticate(decodedAuthentication)
    }
  }

  private fun decodeCredentials(credentials: String): String? = try {
    URLDecoder.decode(credentials, StandardCharsets.UTF_8.toString())
  } catch (e: Exception) {
    throw OAuth2AuthenticationException(OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT), e)
  }

  override fun supports(authentication: Class<*>): Boolean = OAuth2ClientAuthenticationToken::class.java.isAssignableFrom(authentication)
}
