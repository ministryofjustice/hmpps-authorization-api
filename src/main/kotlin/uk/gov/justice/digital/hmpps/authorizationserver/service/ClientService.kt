package uk.gov.justice.digital.hmpps.authorizationserver.service

import org.springframework.security.crypto.keygen.Base64StringKeyGenerator
import org.springframework.security.crypto.keygen.StringKeyGenerator
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import uk.gov.justice.digital.hmpps.authorizationserver.resource.ClientDetails
import java.util.Base64
import java.util.UUID

@Service
class ClientService(
  private val jdbcRegisteredClientRepository: JdbcRegisteredClientRepository,
) {

  private val supportedGrantTypes = setOf(
    AuthorizationGrantType.CLIENT_CREDENTIALS,
    AuthorizationGrantType.DEVICE_CODE,
    AuthorizationGrantType.JWT_BEARER,
    AuthorizationGrantType.PASSWORD, // TODO do we need to support this?
  )

  private val clientSecretGenerator: StringKeyGenerator = Base64StringKeyGenerator(
    Base64.getUrlEncoder().withoutPadding(),
    48,
  )

  @Transactional
  fun add(clientDetails: ClientDetails) {
    jdbcRegisteredClientRepository.save(buildRegisteredClient(clientDetails))
  }

  private fun buildRegisteredClient(clientDetails: ClientDetails): RegisteredClient {
    val registeredClientBuilder = RegisteredClient
      .withId(UUID.randomUUID().toString())
      .clientId(clientDetails.clientId)
      .clientName(clientDetails.clientName)
      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // TODO do we need to support other authentication methods?
      .clientSecret(clientSecretGenerator.generateKey())
      .clientSettings(
        ClientSettings.builder()
          .requireProofKey(false)
          .requireAuthorizationConsent(false).build(),
      )
      .tokenSettings(
        TokenSettings.builder()
          .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
          .build(),
      )

    if (clientDetails.scopes.isNotEmpty()) {
      registeredClientBuilder.scopes { it.addAll(clientDetails.scopes) }
    }

    if (clientDetails.authorizationGrantTypes.isEmpty()) {
      // TODO trigger bad request response
    }

    val acceptableGrantTypes =
      clientDetails.authorizationGrantTypes.filter { supportedGrantTypes.contains(AuthorizationGrantType(it)) }

    if (acceptableGrantTypes.isEmpty()) {
      // TODO trigger bad request response
    }

    acceptableGrantTypes.forEach {
      registeredClientBuilder.authorizationGrantType(AuthorizationGrantType(it))
    }

    return registeredClientBuilder.build()
  }
}
