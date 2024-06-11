package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.UserAuthorizationCode
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.UserAuthorizationCodeRepository
import uk.gov.justice.digital.hmpps.authorizationapi.security.AuthenticatedUserDetails
import java.time.Instant
import java.util.Objects

class UserAuthenticationService(
  private val delegateOAuth2AuthorizationService: OAuth2AuthorizationService,
  private val userAuthorizationCodeRepository: UserAuthorizationCodeRepository,
) : OAuth2AuthorizationService {

  override fun save(authorization: OAuth2Authorization) {
    delegateOAuth2AuthorizationService.save(authorization)
    if (SecurityContextHolder.getContext().authentication is UsernamePasswordAuthenticationToken) {
      val authentication = SecurityContextHolder.getContext().authentication as UsernamePasswordAuthenticationToken
      val authenticatedUserDetails = authentication.principal as AuthenticatedUserDetails
      val userAuthorizationCode = UserAuthorizationCode(
        id = authorization.id,
        username = authentication.name,
        userId = Objects.toString(authenticatedUserDetails.userId, authentication.name),
        userUuid = authenticatedUserDetails.uuid,
        name = authenticatedUserDetails.name,
        authSource = AuthSource.fromNullableString(authenticatedUserDetails.authSource),
        authorizationCodeIssuedAt = Instant.now(),
      )
      userAuthorizationCodeRepository.save(userAuthorizationCode)
    }
  }

  override fun remove(authorization: OAuth2Authorization?) {
    authorization?.let {
      userAuthorizationCodeRepository.deleteAllById(listOf(it.id))
    }

    delegateOAuth2AuthorizationService.remove(authorization)
  }

  override fun findById(id: String?): OAuth2Authorization? {
    return delegateOAuth2AuthorizationService.findById(id)
  }

  override fun findByToken(token: String?, tokenType: OAuth2TokenType?): OAuth2Authorization? {
    return delegateOAuth2AuthorizationService.findByToken(token, tokenType)
  }
}
