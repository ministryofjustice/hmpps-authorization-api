package uk.gov.justice.digital.hmpps.authorizationserver.service

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator
import org.springframework.security.crypto.keygen.StringKeyGenerator
import org.springframework.security.jackson2.SecurityJackson2Modules
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.AuthorizationConsent
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.Client
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientConfig
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.AuthorizationConsentRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientRepository
import uk.gov.justice.digital.hmpps.authorizationserver.resource.ClientDetails
import java.time.Instant
import java.util.Base64
import java.util.UUID

@Service
class ClientService(
  private val clientRepository: ClientRepository,
  private val clientConfigRepository: ClientConfigRepository,
  private val authorizationConsentRepository: AuthorizationConsentRepository,
) {
  private val objectMapper = ObjectMapper()

  init {
    // TODO Move to configuration class
    val classLoader = OAuth2AuthorizationServerJackson2Module::class.java.classLoader
    val securityModules = SecurityJackson2Modules.getModules(classLoader)
    objectMapper.registerModules(securityModules)
    objectMapper.registerModule(OAuth2AuthorizationServerJackson2Module())
  }

  private val clientSecretGenerator: StringKeyGenerator = Base64StringKeyGenerator(
    Base64.getUrlEncoder().withoutPadding(),
    48,
  )

  @Transactional
  fun add(clientDetails: ClientDetails) {
    // TODO this logic assumes creating new - needs safety check to confirm - revert to update instead if not, or fail validation?

    val client = clientRepository.save(buildNewClient(clientDetails))
    authorizationConsentRepository.save(AuthorizationConsent(client.id!!, client.clientId, clientDetails.authorities))

    // TODO do we need to resolve client id to base client id first here?
    clientConfigRepository.save(ClientConfig(client.clientId, clientDetails.ips, null))
  }

  private fun buildNewClient(clientDetails: ClientDetails): Client {
    with(clientDetails) {
      return Client(
        id = UUID.randomUUID().toString(),
        clientId = clientId, // TODO do we need to generate this?
        clientIdIssuedAt = Instant.now(),
        clientSecret = clientSecretGenerator.generateKey(),
        clientSecretExpiresAt = null,
        clientName = clientName,
        clientAuthenticationMethods = ClientAuthenticationMethod.CLIENT_SECRET_BASIC.value,
        authorizationGrantTypes = authorizationGrantTypes.joinToString(separator = ",") { it },
        scopes = scopes.joinToString(separator = ",") { it },
        clientSettings = objectMapper.writeValueAsString(
          ClientSettings.builder()
            .requireProofKey(false)
            .requireAuthorizationConsent(false).build().settings,
        ),
        tokenSettings = objectMapper.writeValueAsString(
          TokenSettings.builder()
            .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
            .build().settings,
        ),
      )
    }
  }
}
