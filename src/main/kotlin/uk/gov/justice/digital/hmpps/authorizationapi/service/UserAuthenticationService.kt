package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType

class UserAuthenticationService(
  private val delegateOAuth2AuthorizationService: OAuth2AuthorizationService,
) : OAuth2AuthorizationService {

  override fun save(authorization: OAuth2Authorization?) {
    delegateOAuth2AuthorizationService.save(authorization)
  }

  override fun remove(authorization: OAuth2Authorization?) {
    delegateOAuth2AuthorizationService.remove(authorization)
  }

  override fun findById(id: String?): OAuth2Authorization? {
    return delegateOAuth2AuthorizationService.findById(id)
  }

  override fun findByToken(token: String?, tokenType: OAuth2TokenType?): OAuth2Authorization? {
    return delegateOAuth2AuthorizationService.findByToken(token, tokenType)
  }
}
