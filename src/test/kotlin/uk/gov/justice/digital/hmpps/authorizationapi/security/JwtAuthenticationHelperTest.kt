package uk.gov.justice.digital.hmpps.authorizationapi.security

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import uk.gov.justice.digital.hmpps.authorizationapi.integration.IntegrationTestBase
import uk.gov.justice.digital.hmpps.authorizationapi.service.AuthSource
import uk.gov.justice.digital.hmpps.authorizationapi.service.JWKKeyAccessor
import java.security.PrivateKey
import java.time.Duration
import java.util.Date

class JwtAuthenticationHelperTest : IntegrationTestBase() {

  @Autowired
  private lateinit var jwkKeyAccessor: JWKKeyAccessor

  @Autowired
  private lateinit var jwtAuthenticationHelper: JwtAuthenticationHelper

  private val username: String = "username"
  private val jwtId: String = "9999"

  @Test
  fun readTokenSignedWithPrimaryKey() {
    val claims = claims()
    val token = createJwtWith(username, jwtId, claims, Duration.ofHours(2), jwkKeyAccessor.getPrimaryKeyPair().private)
    val parsedToken = jwtAuthenticationHelper.readAuthenticationFromJwt(token)

    assertTrue(parsedToken.isPresent)
    val actualToken = parsedToken.get()
    allClaimsMatch(claims, actualToken.principal as AuthenticatedUserDetails)
  }

  @Test
  fun readTokenSignedWithAuxiliaryKey() {
    val claims = claims()
    val token = createJwtWith(username, jwtId, claims, Duration.ofHours(2), jwkKeyAccessor.getAuxiliaryKeyPair()!!.private)
    val parsedToken = jwtAuthenticationHelper.readAuthenticationFromJwt(token)

    assertTrue(parsedToken.isPresent)
    val actualToken = parsedToken.get()
    allClaimsMatch(claims, actualToken.principal as AuthenticatedUserDetails)
  }

  @Test
  fun readTokenWithMissingClaims() {
    val authenticatedUserDetails = claims(name = null, authSource = null, authorities = emptyList(), userId = null)
    val token = createJwtWith(username, jwtId, authenticatedUserDetails, Duration.ofHours(2), jwkKeyAccessor.getPrimaryKeyPair().private)
    val parsedUserDetails = jwtAuthenticationHelper.readAuthenticationFromJwt(token)

    assertTrue(parsedUserDetails.isPresent)
    claimsMissingMatch(parsedUserDetails.get().principal as AuthenticatedUserDetails)
  }

  private fun claimsMissingMatch(actualUserDetails: AuthenticatedUserDetails) {
    assertThat(actualUserDetails.authorities).isEmpty()
    assertThat(actualUserDetails.name).isEqualTo(username)
    assertThat(actualUserDetails.authSource).isEqualTo(AuthSource.None.source)
    assertThat(actualUserDetails.userId).isEqualTo(username)
    assertThat(actualUserDetails.passedMfa).isEqualTo(false)
    assertThat(actualUserDetails.jwtId).isEqualTo(jwtId)
  }

  private fun allClaimsMatch(expectedClaims: Map<String, Any?>, actualUserDetails: AuthenticatedUserDetails) {
    assertThat(expectedClaims["authorities"] as List<*>).containsAll(actualUserDetails.authorities)
    assertThat(expectedClaims["name"]).isEqualTo(actualUserDetails.name)
    assertThat(expectedClaims["auth_source"]).isEqualTo(actualUserDetails.authSource)
    assertThat(expectedClaims["user_id"]).isEqualTo(actualUserDetails.userId)
    assertThat(expectedClaims["passed_mfa"]).isEqualTo(actualUserDetails.passedMfa)
    assertThat(actualUserDetails.jwtId).isEqualTo(jwtId)
  }

  private fun claims(
    name: String? = "name",
    authorities: Collection<GrantedAuthority> = listOf(SimpleGrantedAuthority("ROLE_TEST")),
    authSource: String? = AuthSource.None.name,
    userId: String? = "1234",
    passedMfa: Boolean = false,
  ) = mapOf(
    "authorities" to authorities,
    "name" to name,
    "auth_source" to authSource,
    "user_id" to userId,
    "passed_mfa" to passedMfa,
  )

  fun createJwtWith(username: String, jwtId: String, claims: Map<String, Any?>, expiryTime: Duration, key: PrivateKey): String {
    val authoritiesAsString = (claims["authorities"] as? Collection<*>)?.joinToString(separator = ",") { (it as GrantedAuthority).authority } ?: ""

    return Jwts.builder()
      .setId(jwtId)
      .setSubject(username)
      .addClaims(
        mapOf(
          "authorities" to authoritiesAsString,
          "name" to claims["name"],
          "auth_source" to claims["auth_source"],
          "user_id" to claims["user_id"],
          "passed_mfa" to claims["passed_mfa"],
        ),
      )
      .setExpiration(Date(System.currentTimeMillis() + expiryTime.toMillis()))
      .signWith(SignatureAlgorithm.RS256, key)
      .compact()
  }
}
