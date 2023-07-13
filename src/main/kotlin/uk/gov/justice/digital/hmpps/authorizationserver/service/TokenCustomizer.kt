package uk.gov.justice.digital.hmpps.authorizationserver.service

import org.apache.commons.lang3.StringUtils.isNotEmpty
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationserver.service.AuthSource.Companion.fromNullableString
import java.util.UUID
import java.util.stream.Collectors

@Component
class TokenCustomizer(
  private val authorizationConsentService: OAuth2AuthorizationConsentService,
  private val registeredClientAdditionalInformation: RegisteredClientAdditionalInformation,
) : OAuth2TokenCustomizer<JwtEncodingContext> {

  companion object {
    private const val REQUEST_PARAM_USER_NAME = "username"
    private const val REQUEST_PARAM_AUTH_SOURCE = "auth_source"
  }

  override fun customize(context: JwtEncodingContext?) {
    context?.let {
        jwtEncodingContext ->

      if (jwtEncodingContext.getPrincipal<Authentication>() is OAuth2ClientAuthenticationToken) {
        val principal = jwtEncodingContext.getPrincipal<Authentication>() as OAuth2ClientAuthenticationToken
        addClientAuthorities(jwtEncodingContext, principal)
        customizeClientCredentials(jwtEncodingContext, principal)
      } else if (jwtEncodingContext.getPrincipal<Authentication>() is UsernamePasswordAuthenticationToken) {
        addEndUserAuthorities(jwtEncodingContext, jwtEncodingContext.getPrincipal<Authentication>() as UsernamePasswordAuthenticationToken)
      }
    }
  }

  private fun addEndUserAuthorities(context: JwtEncodingContext, principal: UsernamePasswordAuthenticationToken) {
    addAuthorities(context, principal.authorities)
  }

  private fun addClientAuthorities(context: JwtEncodingContext, principal: OAuth2ClientAuthenticationToken) {
    principal.registeredClient?.let { registeredClient ->
      val oAuth2AuthorizationConsent = authorizationConsentService.findById(registeredClient.id, registeredClient.clientName)

      oAuth2AuthorizationConsent?.let {
        addAuthorities(context, it.authorities)
      }
    }
  }

  private fun addAuthorities(context: JwtEncodingContext, grantedAuthorities: Collection<GrantedAuthority>) {
    val authorities = grantedAuthorities.stream().map { obj: GrantedAuthority -> obj.authority }
      .collect(Collectors.toSet())
    context.claims.claim("authorities", authorities)
  }

  private fun customizeClientCredentials(context: JwtEncodingContext, principal: OAuth2ClientAuthenticationToken) {
    with(context.claims) {
      val token: OAuth2ClientCredentialsAuthenticationToken? = context.getAuthorizationGrant()
      token?.let {
        if (it.additionalParameters.containsKey(REQUEST_PARAM_USER_NAME) && isNotEmpty(token.additionalParameters[REQUEST_PARAM_USER_NAME] as String)) {
          claim("user_name", it.additionalParameters[REQUEST_PARAM_USER_NAME])
          claim("sub", it.additionalParameters[REQUEST_PARAM_USER_NAME])
        }

        claim("auth_source", fromNullableString(it.additionalParameters[REQUEST_PARAM_AUTH_SOURCE] as String?).source)
        registeredClientAdditionalInformation.getDatabaseUserName(principal.registeredClient?.tokenSettings)?.let { databaseUsername ->
          claim("database_username", databaseUsername)
        }
      }

      claim("client_id", principal.registeredClient?.clientId ?: "Unknown")
      claim("scope", principal.registeredClient?.scopes)
      claim("grant_type", context.authorizationGrantType.value)
      claim("jti", UUID.randomUUID().toString())
    }
  }
}
