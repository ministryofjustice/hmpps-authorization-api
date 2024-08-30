package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.slf4j.LoggerFactory
import org.springframework.security.authentication.AuthenticationProvider
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
        val clientAuthentication = authentication as OAuth2ClientAuthenticationToken
        val decodedAuthentication = OAuth2ClientAuthenticationToken(
          clientAuthentication.principal.toString(),
          clientAuthentication.clientAuthenticationMethod,
          URLDecoder.decode(it.toString(), StandardCharsets.UTF_8.toString()),
          clientAuthentication.additionalParameters,
        )

        delegate.authenticate(decodedAuthentication)
      }
    }
  }

  override fun supports(authentication: Class<*>): Boolean {
    return OAuth2ClientAuthenticationToken::class.java.isAssignableFrom(authentication)
  }
}
