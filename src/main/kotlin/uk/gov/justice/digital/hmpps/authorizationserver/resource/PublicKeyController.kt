package uk.gov.justice.digital.hmpps.authorizationserver.resource

import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag
import org.apache.commons.codec.binary.Base64
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.security.PublicKey
import uk.gov.justice.digital.hmpps.authorizationserver.service.JWKKeyAccessor


@Tag(name = "jwt-public-key")
@RestController
class PublicKeyController @Autowired constructor(
  jwkKeyAccessor: JWKKeyAccessor,
) {
  private val publicKey: PublicKey

  @RequestMapping(value = ["jwt-public-key"], produces = [MediaType.APPLICATION_JSON_VALUE])
  @Operation(summary = "Public JWT Key", description = " ")
  fun getJwtPublicKey(): Map<String, Any> {
    val formattedKey = getFormattedKey(publicKey)
    return mapOf(
      "formatted" to convertNewLinesToArray(formattedKey),
      "encoded" to Base64.encodeBase64String(formattedKey.toByteArray()),
    )
  }

  private fun convertNewLinesToArray(formattedKey: String): Array<String> =
    formattedKey.split("\n".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

  private fun getFormattedKey(pk: PublicKey): String {
    val builder = StringBuilder()
    val encodeBase64String = Base64.encodeBase64String(pk.encoded)
    builder.append("-----BEGIN PUBLIC KEY-----")
    builder.append("\n")
    var i = 0
    while (i < encodeBase64String.length) {
      builder.append(encodeBase64String, i, Math.min(i + 64, encodeBase64String.length))
      builder.append("\n")
      i += 64
    }
    builder.append("-----END PUBLIC KEY-----")
    builder.append("\n")
    return builder.toString()
  }

  init {
    publicKey = jwkKeyAccessor.getPrimaryKeyPair().public
  }
}
