package uk.gov.justice.digital.hmpps.authorizationserver.service

import org.apache.commons.codec.binary.Base64.decodeBase64
import org.apache.commons.lang3.ObjectUtils
import org.springframework.beans.factory.annotation.Value
import org.springframework.core.io.ByteArrayResource
import org.springframework.stereotype.Component
import java.io.InputStream
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
  @Value("#{'\${jwt.auxiliary.keystore.alias}' <= '' ? null : '\${jwt.auxiliary.keystore.alias}'}") private val keystoreAliasAuxiliary: String?,
  @Value("#{'\${jwt.auxiliary.keystore.password}' <= '' ? null : '\${jwt.auxiliary.keystore.password}'}") private val keystorePasswordAuxiliary: String?,
  @Value("#{'\${jwt.auxiliary.signing.key.pair}' <= '' ? null : '\${jwt.auxiliary.signing.key.pair}'}") private val privateKeyPairAuxiliary: String?,
  @Value("#{'\${jwt.auxiliary.jwk.key.id}' <= '' ? null : '\${jwt.auxiliary.jwk.key.id}'}") private val keyIdAuxiliary: String?,
) {
  private val primaryKeyStore: KeyStore = initializePrimaryKeyStore()
  private val auxiliaryKeyStore: KeyStore = initializeAuxiliaryKeyStore()
  fun getPrimaryKeyPair(): KeyPair {
    val privateKey = primaryKeyStore.getKey(keystoreAlias, keystorePassword.toCharArray()) as? RSAPrivateCrtKey
    val rsaPublicKeySpec = RSAPublicKeySpec(privateKey!!.modulus, privateKey.publicExponent)
    val publicKey = KeyFactory.getInstance("RSA").generatePublic(rsaPublicKeySpec)
    return KeyPair(publicKey, privateKey)
  }
  fun getAuxiliaryKeyPair(): KeyPair? {
    return if (ObjectUtils.anyNull(keystoreAliasAuxiliary, keystorePasswordAuxiliary, keyIdAuxiliary)) {
      null
    } else {
      val privateKey =
        auxiliaryKeyStore.getKey(keystoreAliasAuxiliary, keystorePasswordAuxiliary!!.toCharArray()) as RSAPrivateCrtKey
      val rsaPublicKeySpec = RSAPublicKeySpec(privateKey.modulus, privateKey.publicExponent)
      val publicKey = KeyFactory.getInstance("RSA").generatePublic(rsaPublicKeySpec)
      return KeyPair(publicKey, privateKey)
    }
  }
  private fun initializePrimaryKeyStore(): KeyStore {
    val store = KeyStore.getInstance("jks")
    val primaryStoreInputStream = ByteArrayResource(decodeBase64(privateKeyPair)).inputStream

    primaryStoreInputStream.use {
      store.load(it, keystorePassword.toCharArray())
    }

    return store
  }
  private fun initializeAuxiliaryKeyStore(): KeyStore {
    val store = KeyStore.getInstance("jks")
    val auxiliaryKeyStoreInputStream: InputStream? = privateKeyPairAuxiliary?.let { ByteArrayResource(decodeBase64(it)) }?.inputStream

    auxiliaryKeyStoreInputStream.use {
      store.load(it, keystorePasswordAuxiliary?.toCharArray())
    }
    return store
  }
}
