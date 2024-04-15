package uk.gov.justice.digital.hmpps.authorizationapi.security

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.SignatureException
import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationapi.service.JWKKeyAccessor

@Component
class SignedJwtParser(
  jwkKeyAccessor: JWKKeyAccessor,
) {
  private val keyPair = jwkKeyAccessor.getPrimaryKeyPair()
  private val keyPairAuxiliary = jwkKeyAccessor.getAuxiliaryKeyPair()

  fun parseSignedJwt(jwt: String): Claims =
    try {
      Jwts.parser().verifyWith(keyPair.public).build().parseSignedClaims(jwt).payload
    } catch (ex: SignatureException) {
      if (keyPairAuxiliary == null) {
        throw ex
      }
      Jwts.parser().verifyWith(keyPairAuxiliary.public).build().parseSignedClaims(jwt).payload
    }
}
