package uk.gov.justice.digital.hmpps.authorizationserver.service

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.stereotype.Component
import java.util.stream.Collectors

@Component
class AuthoritiesTokenCustomizer(
  private val authorizationConsentService: OAuth2AuthorizationConsentService,
) : OAuth2TokenCustomizer<JwtEncodingContext> {

  override fun customize(context: JwtEncodingContext?) {
    context?.let {
        jwtEncodingContext ->

      if (jwtEncodingContext.getPrincipal<Authentication>() is OAuth2ClientAuthenticationToken) {
        val principal = jwtEncodingContext.getPrincipal<Authentication>() as OAuth2ClientAuthenticationToken
        addClientAuthoritiesTo(jwtEncodingContext, principal)
        addClientId(jwtEncodingContext, principal)
      } else if (jwtEncodingContext.getPrincipal<Authentication>() is UsernamePasswordAuthenticationToken) {
        addEndUserAuthoritiesTo(jwtEncodingContext, jwtEncodingContext.getPrincipal<Authentication>() as UsernamePasswordAuthenticationToken)
      }
    }
  }

  private fun addEndUserAuthoritiesTo(context: JwtEncodingContext, principal: UsernamePasswordAuthenticationToken) {
    addAuthorities(context, principal.authorities)
  }

  private fun addClientAuthoritiesTo(context: JwtEncodingContext, principal: OAuth2ClientAuthenticationToken) {
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

  private fun addClientId(context: JwtEncodingContext, principal: OAuth2ClientAuthenticationToken) {
    context.claims.claim("client_id", principal.registeredClient?.clientId ?: "Unknown")
  }
}
