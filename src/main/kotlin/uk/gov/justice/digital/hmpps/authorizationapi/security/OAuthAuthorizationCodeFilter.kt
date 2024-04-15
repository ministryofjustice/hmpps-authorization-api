package uk.gov.justice.digital.hmpps.authorizationapi.security

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.web.filter.OncePerRequestFilter

class OAuthAuthorizationCodeFilter(
  private val signedJwtParser: SignedJwtParser,
) : OncePerRequestFilter() {

  override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
    val authorizationHeader = request.getHeader("Authorization")
    if (authorizationHeader == null) {
      log.error("Call received to authorize end point without required token")
      sendUnauthorisedErrorResponse(response)
    } else {
      try {
        val claims = signedJwtParser.parseSignedJwt(authorizationHeader)
        val authoritiesString = claims.get("authorities", String::class.java)
        val authorities: Collection<GrantedAuthority> = authoritiesString.split(",")
          .filterNot { authority -> authority.isEmpty() }
          .map { authority -> SimpleGrantedAuthority(authority) }

        if (!authorities.contains(SimpleGrantedAuthority(AUTHORIZE_ROLE))) {
          log.error("Token presented to authorize end point does not contain required role")
          sendUnauthorisedErrorResponse(response)
        } else {
          log.info("Allowing access of authorised call to authorize end point")
          filterChain.doFilter(request, response)
        }
      } catch (e: Exception) {
        log.error("Failed to parse token presented to authorize end point", e)
        sendUnauthorisedErrorResponse(response)
      }
    }
  }

  private fun sendUnauthorisedErrorResponse(response: HttpServletResponse) {
    response.status = HttpStatus.UNAUTHORIZED.value()
    response.flushBuffer()
  }

  companion object {
    private const val AUTHORIZE_ROLE = "ROLE_AUTH_AUTHORIZE"
    private val log = LoggerFactory.getLogger(this::class.java)
  }
}
