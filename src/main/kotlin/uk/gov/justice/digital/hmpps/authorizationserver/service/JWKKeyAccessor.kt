package uk.gov.justice.digital.hmpps.authorizationserver.service

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
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
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec

@Component
class JWKKeyAccessor(
  @Value("\${jwt.signing.key.pair}") private val privateKeyPair: String,
  @Value("\${jwt.keystore.password}") private val keystorePassword: String,
  @Value("\${jwt.keystore.alias:elite2api}") private val keystoreAlias: String,
  @Value("\${jwt.jwk.key.id}") private val keyId: String,
  @Value("#{'\${jwt.auxiliary.keystore.alias}' <= '' ? null : '\${jwt.auxiliary.keystore.alias}'}") private val keystoreAliasAuxiliary: String?,
  @Value("#{'\${jwt.auxiliary.keystore.password}' <= '' ? null : '\${jwt.auxiliary.keystore.password}'}") private val keystorePasswordAuxiliary: String?,
  @Value("#{'\${jwt.auxiliary.signing.key.pair}' <= '' ? null : '\${jwt.auxiliary.signing.key.pair}'}") private val privateKeyPairAuxiliary: String?,
  @Value("#{'\${jwt.auxiliary.jwk.key.id}' <= '' ? null : '\${jwt.auxiliary.jwk.key.id}'}") private val keyIdAuxiliary: String?,
) {
  private val primaryKeyStore: KeyStore = initializePrimaryKeyStore()
  private val auxiliaryKeyStore: KeyStore = initializeAuxiliaryKeyStore()

  fun getPrimaryKeyPair() = getKeyPair(primaryKeyStore, keystoreAlias, keystorePassword)

  fun getAuxiliaryKeyPair(): KeyPair? {
    return if (ObjectUtils.anyNull(keystoreAliasAuxiliary, keystorePasswordAuxiliary, keyIdAuxiliary)) {
      null
    } else {
      return getKeyPair(auxiliaryKeyStore, keystoreAliasAuxiliary, keystorePasswordAuxiliary)
    }
  }

  fun getAuxiliaryPublicKey(): RSAKey? {
    return if (ObjectUtils.anyNull(keyIdAuxiliary, keystoreAliasAuxiliary, keystorePasswordAuxiliary, privateKeyPairAuxiliary)) {
      null
    } else {
      return buildRSAKey(getAuxiliaryKeyPair()!!, keyIdAuxiliary!!)
    }
  }

  fun getPrimaryPublicKey() = buildRSAKey(getPrimaryKeyPair(), keyId)

  private fun getKeyPair(keyStore: KeyStore, keystoreAlias: String?, keystorePassword: String?): KeyPair {
    val privateKey =
      keyStore.getKey(keystoreAlias, keystorePassword!!.toCharArray()) as RSAPrivateCrtKey
    val rsaPublicKeySpec = RSAPublicKeySpec(privateKey.modulus, privateKey.publicExponent)
    val publicKey = KeyFactory.getInstance("RSA").generatePublic(rsaPublicKeySpec)
    return KeyPair(publicKey, privateKey)
  }

  private fun initializeKeyStore(privateKeyPair: String?, keystorePassword: String?): KeyStore {
    val store = KeyStore.getInstance("jks")
    val auxiliaryKeyStoreInputStream: InputStream? = privateKeyPair?.let { ByteArrayResource(decodeBase64(it)) }?.inputStream

    auxiliaryKeyStoreInputStream.use {
      store.load(it, keystorePassword?.toCharArray())
    }
    return store
  }

  private fun initializePrimaryKeyStore() = initializeKeyStore(privateKeyPair, keystorePassword)

  private fun initializeAuxiliaryKeyStore() = initializeKeyStore(privateKeyPairAuxiliary, keystorePasswordAuxiliary)

  private fun buildRSAKey(keyPair: KeyPair, keyId: String): RSAKey {
    return keyPair.let { RSAKey.Builder(it.public as? RSAPublicKey) }
      .keyUse(KeyUse.SIGNATURE)
      .algorithm(JWSAlgorithm.RS256)
      .keyID(keyId).build()
  }
}
