package uk.gov.justice.digital.hmpps.authorizationapi.security

import io.jsonwebtoken.ExpiredJwtException
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationapi.service.AuthSource
import java.util.Optional

@Component
class JwtAuthenticationHelper(
  private val signedJwtParser: SignedJwtParser,
) {

  fun readAuthenticationFromJwt(jwt: String): Optional<UsernamePasswordAuthenticationToken> = readUserDetailsFromJwt(jwt).map { UsernamePasswordAuthenticationToken(it, null, it.authorities) }

  private fun readUserDetailsFromJwt(jwt: String): Optional<AuthenticatedUserDetails> = try {
    val body = signedJwtParser.parseSignedJwt(jwt)
    val username = body.subject
    val authoritiesString = body.get("authorities", String::class.java)
    val name = body.get("name", String::class.java) ?: username
    val userId = body.get("user_id", String::class.java) ?: username
    val authorities: Collection<GrantedAuthority> = authoritiesString.split(",").filterNot { it.isEmpty() }
      .map { SimpleGrantedAuthority(it) }
    val authSource = body.get("auth_source", String::class.java) ?: AuthSource.None.source
    val uuid = body.get("uuid", String::class.java)

    log.debug("Set authentication for {} with jwt id of {}", username, body.id)
    Optional.of(AuthenticatedUserDetails(username, name, authorities, authSource, userId, body.id, uuid))
  } catch (eje: ExpiredJwtException) {
    log.info("Expired JWT found for user {}", eje.claims.subject)
    Optional.empty()
  }

  companion object {
    private val log = LoggerFactory.getLogger(this::class.java)
  }
}
