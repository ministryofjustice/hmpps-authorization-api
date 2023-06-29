package uk.gov.justice.digital.hmpps.authorizationserver.service

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator
import org.springframework.security.crypto.keygen.StringKeyGenerator
import org.springframework.security.jackson2.SecurityJackson2Modules
import org.springframework.security.oauth2.core.AuthorizationGrantType
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
  fun addClientCredentials(clientDetails: ClientDetails) {
    val existingClient = clientRepository.findClientByClientId(clientDetails.clientId)
    existingClient?.let {
      throw ClientAlreadyExistsException(clientDetails.clientId)
    }

    val client = clientRepository.save(buildNewClient(clientDetails))
    authorizationConsentRepository.save(AuthorizationConsent(client.id!!, client.clientId, clientDetails.authorities))
    clientConfigRepository.save(ClientConfig(client.clientId, clientDetails.ips, null))
  }

  private fun buildNewClient(clientDetails: ClientDetails): Client {
    with(clientDetails) {
      return Client(
        id = UUID.randomUUID().toString(),
        clientId = clientId,
        clientIdIssuedAt = Instant.now(),
        clientSecret = clientSecretGenerator.generateKey(),
        clientSecretExpiresAt = null,
        clientName = clientName,
        clientAuthenticationMethods = ClientAuthenticationMethod.CLIENT_SECRET_BASIC.value,
        authorizationGrantTypes = AuthorizationGrantType.CLIENT_CREDENTIALS.value,
        scopes = scopes,
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

class ClientAlreadyExistsException(clientId: String) : RuntimeException("Client with client id $clientId cannot be created as already exists")
