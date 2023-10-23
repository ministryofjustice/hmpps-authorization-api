package uk.gov.justice.digital.hmpps.authorizationserver.security

import io.jsonwebtoken.Claims
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureException
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationserver.service.JWKKeyAccessor
import java.security.KeyPair
import java.time.Duration
import java.util.Optional

@Component
class JwtAuthenticationHelper(
  jwkKeyAccessor: JWKKeyAccessor,
) {
  private val keyPair: KeyPair = jwkKeyAccessor.getPrimaryKeyPair()
  private val expiryTime: Duration = Duration.ofDays(1) // TODO this needs to come from configuration

  companion object {
    private val log = LoggerFactory.getLogger(this::class.java)
  }

  fun readAuthenticationFromJwt(jwt: String): Optional<UsernamePasswordAuthenticationToken> =
    readUserDetailsFromJwt(jwt).map { UsernamePasswordAuthenticationToken(it, null, it.authorities) }

  fun readUserDetailsFromJwt(jwt: String): Optional<UserDetailsImpl> = try {
    val body = parseSignedJwt(jwt)
    val username = body.subject
    val authoritiesString = body.get("authorities", String::class.java)
    val name = body.get("name", String::class.java) ?: username
    val userId = body.get("user_id", String::class.java) ?: username
    val authorities: Collection<GrantedAuthority> = authoritiesString.split(",").filterNot { it.isEmpty() }
      .map { SimpleGrantedAuthority(it) }
    val authSource = body.get("auth_source", String::class.java) ?: AuthSource.none.source
    val passedMfa = body.get("passed_mfa", java.lang.Boolean::class.java) ?.booleanValue() ?: false

    log.debug("Set authentication for {} with jwt id of {}", username, body.id)
    Optional.of(UserDetailsImpl(username, name, authorities, authSource, userId, body.id, passedMfa))
  } catch (eje: ExpiredJwtException) {
    // cookie set to expire at same time as JWT so unlikely really get an expired one
    log.info("Expired JWT found for user {}", eje.claims.subject)
    Optional.empty()
  }

  fun parseSignedJwt(jwt: String): Claims =
    try {
      Jwts.parser().setSigningKey(keyPair.public).parseClaimsJws(jwt)
    } catch (ex: SignatureException) {
      throw RuntimeException("Need to use auxiliary key pair instead of doing this!") // TODO use auxiliary key pair instead
    }
      .body
}
