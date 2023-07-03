package uk.gov.justice.digital.hmpps.authorizationserver.service

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientMetadataClaimNames
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationToken

class OidcRegistrationAdditionalDataHandler(
  private val delegate: AuthenticationProvider,
  private val registeredClientAdditionalInformation: RegisteredClientAdditionalInformation,
  private val registeredClientDataService: RegisteredClientDataService,
) : AuthenticationProvider {

  override fun authenticate(authentication: Authentication?): Authentication {
    val clientRegistrationAuthentication = authentication as OidcClientRegistrationAuthenticationToken

    val authenticationResult = delegate.authenticate(authentication).let {
      val claims = clientRegistrationAuthentication.clientRegistration.claims
      registeredClientDataService.updateAdditionalInformation(
        claims[OidcClientMetadataClaimNames.CLIENT_ID].toString(),
        registeredClientAdditionalInformation.mapFrom(claims),
      )

      return@let it
    }

    return authenticationResult
  }

  override fun supports(authentication: Class<*>): Boolean {
    return OidcClientRegistrationAuthenticationToken::class.java.isAssignableFrom(authentication)
  }
}
