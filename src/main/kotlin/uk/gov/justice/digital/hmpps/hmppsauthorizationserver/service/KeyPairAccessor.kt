package uk.gov.justice.digital.hmpps.hmppsauthorizationserver.service

import org.apache.commons.codec.binary.Base64.decodeBase64
import org.springframework.beans.factory.annotation.Value
import org.springframework.core.io.ByteArrayResource
import org.springframework.stereotype.Component
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyStore
import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.RSAPublicKeySpec

@Component
class KeyPairAccessor(
  @Value("\${jwt.signing.key.pair}") private val privateKeyPair: String,
  @Value("\${jwt.keystore.password}") private val keystorePassword: String,
  @Value("\${jwt.keystore.alias:elite2api}") private val keystoreAlias: String,
) {
  private val keyStore: KeyStore = initializeKeyStore()

  fun getKeyPair(): KeyPair {
    val privateKey = keyStore.getKey(keystoreAlias, keystorePassword.toCharArray()) as RSAPrivateCrtKey
    val rsaPublicKeySpec = RSAPublicKeySpec(privateKey.modulus, privateKey.publicExponent)
    val publicKey = KeyFactory.getInstance("RSA").generatePublic(rsaPublicKeySpec)
    return KeyPair(publicKey, privateKey)
  }

  private fun initializeKeyStore(): KeyStore {
    val store = KeyStore.getInstance("jks")
    val keyStoreInputStream = ByteArrayResource(decodeBase64(privateKeyPair)).inputStream
    keyStoreInputStream.use {
      store.load(it, keystorePassword.toCharArray())
    }
    return store
  }
}
