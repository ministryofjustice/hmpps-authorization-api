package uk.gov.justice.digital.hmpps.authorizationapi.integration

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.springframework.http.HttpHeaders
import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationapi.service.JWKKeyAccessor
import java.time.Duration
import java.util.Date
import java.util.UUID

@Component
class JwtAuthHelper(private val keyPair: JWKKeyAccessor) {

  fun setAuthorisation(
    user: String = "hmpps-manage-users",
    roles: List<String> = listOf(),
    scopes: List<String> = listOf(),
  ): (HttpHeaders) -> Unit {
    val token = createJwt(
      subject = user,
      scope = scopes,
      expiryTime = Duration.ofHours(1L),
      roles = roles,
    )
    return { it.set(HttpHeaders.AUTHORIZATION, "Bearer $token") }
  }

  internal fun createJwt(
    subject: String?,
    scope: List<String>? = listOf(),
    roles: List<String>? = listOf(),
    expiryTime: Duration = Duration.ofHours(1),
    jwtId: String = UUID.randomUUID().toString(),
  ): String = mutableMapOf<String, Any>()
    .also { subject?.let { subject -> it["user_name"] = subject } }
    .also { it["client_id"] = "hmpps-manage-users" }
    .also { roles?.let { roles -> it["authorities"] = roles } }
    .also { scope?.let { scope -> it["scope"] = scope } }
    .let {
      Jwts.builder()
        .setId(jwtId)
        .setSubject(subject)
        .addClaims(it.toMap())
        .setExpiration(Date(System.currentTimeMillis() + expiryTime.toMillis()))
        .signWith(SignatureAlgorithm.RS256, keyPair.getPrimaryKeyPair().private)
        .compact()
    }
}
