package uk.gov.justice.digital.hmpps.authorizationapi.utils

import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.stereotype.Component
import java.security.SecureRandom

@Component
class OAuthClientSecret {

  private val passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()

  // ! $ % & * + - < >
  private val charPoolLimitSpecialChar: List<Char> =
    ('a'..'z') + ('A'..'Z') + '!' + ('$'..'&') + ('*'..'+') + '-' + ('0'..'9') + '<' + '>'
  var randomSpecialChar: SecureRandom = SecureRandom()

  fun encode(secret: String): String = passwordEncoder.encode(secret)
  fun generate(): String = (1..60)
    .map { randomSpecialChar.nextInt(charPoolLimitSpecialChar.size) }
    .map(charPoolLimitSpecialChar::get)
    .joinToString("")
}
