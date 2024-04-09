package uk.gov.justice.digital.hmpps.authorizationapi.utils

import org.apache.commons.codec.binary.Base64.encodeBase64URLSafe
import org.springframework.security.crypto.keygen.KeyGenerators.secureRandom
import org.springframework.stereotype.Component
import java.nio.charset.Charset.forName

@Component
class OAuthJtiGenerator {

  companion object {
    private const val US_ASCII_CHARS_SET = "US-ASCII"
  }

  fun generateTokenId() = String(
    encodeBase64URLSafe(secureRandom(20).generateKey()),
    forName(US_ASCII_CHARS_SET),
  )
}
