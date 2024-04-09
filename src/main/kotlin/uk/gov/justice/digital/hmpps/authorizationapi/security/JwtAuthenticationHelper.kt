package uk.gov.justice.digital.hmpps.authorizationapi.security

import io.jsonwebtoken.Claims
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.SignatureException
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationapi.service.AuthSource
import uk.gov.justice.digital.hmpps.authorizationapi.service.JWKKeyAccessor
import java.util.Optional

@Component
class JwtAuthenticationHelper(
  jwkKeyAccessor: JWKKeyAccessor,
) {
  private val keyPair = jwkKeyAccessor.getPrimaryKeyPair()
  private val keyPairAuxiliary = jwkKeyAccessor.getAuxiliaryKeyPair()

  fun readAuthenticationFromJwt(jwt: String): Optional<UsernamePasswordAuthenticationToken> =
    readUserDetailsFromJwt(jwt).map { UsernamePasswordAuthenticationToken(it, null, it.authorities) }

  private fun readUserDetailsFromJwt(jwt: String): Optional<AuthenticatedUserDetails> = try {
    val body = parseSignedJwt(jwt)
    val username = body.subject
    val authoritiesString = body.get("authorities", String::class.java)
    val name = body.get("name", String::class.java) ?: username
    val userId = body.get("user_id", String::class.java) ?: username
    val authorities: Collection<GrantedAuthority> = authoritiesString.split(",").filterNot { it.isEmpty() }
      .map { SimpleGrantedAuthority(it) }
    val authSource = body.get("auth_source", String::class.java) ?: AuthSource.None.source
    val passedMfa = body.get("passed_mfa", java.lang.Boolean::class.java) ?.booleanValue() ?: false

    log.debug("Set authentication for {} with jwt id of {}", username, body.id)
    Optional.of(AuthenticatedUserDetails(username, name, authorities, authSource, userId, body.id, passedMfa))
  } catch (eje: ExpiredJwtException) {
    log.info("Expired JWT found for user {}", eje.claims.subject)
    Optional.empty()
  }

  private fun parseSignedJwt(jwt: String): Claims =
    try {
      Jwts.parser().verifyWith(keyPair.public).build().parseSignedClaims(jwt).payload
    } catch (ex: SignatureException) {
      if (keyPairAuxiliary == null) {
        throw ex
      }
      Jwts.parser().verifyWith(keyPairAuxiliary.public).build().parseSignedClaims(jwt).payload
    }

  companion object {
    private val log = LoggerFactory.getLogger(this::class.java)
  }
}
