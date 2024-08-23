package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.slf4j.LoggerFactory
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

class UrlDecodingRetryClientSecretAuthenticationProvider(
  private val delegate: AuthenticationProvider,
) : AuthenticationProvider {

  companion object {
    private val log = LoggerFactory.getLogger(this::class.java)
  }

  override fun authenticate(authentication: Authentication?): Authentication? {
    return try {
      delegate.authenticate(authentication)
    } catch (e: OAuth2AuthenticationException) {
      log.info("OAuth2AuthenticationException occurred whilst validating client id and secret, attempting re-try with url decoded credentials")

      authentication?.credentials?.let {
        val decodedAuthentication = UsernamePasswordAuthenticationToken(
          authentication.principal,
          URLDecoder.decode(authentication.credentials.toString(), StandardCharsets.UTF_8.toString()),
          authentication.authorities,
        )
        decodedAuthentication.details = authentication.details

        delegate.authenticate(decodedAuthentication)
      }
    }
  }

  override fun supports(authentication: Class<*>): Boolean {
    return OAuth2ClientAuthenticationToken::class.java.isAssignableFrom(authentication)
  }
}
