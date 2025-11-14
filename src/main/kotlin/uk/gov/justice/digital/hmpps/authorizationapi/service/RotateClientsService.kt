package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.AuthorizationConsent
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.AuthorizationConsent.AuthorizationConsentId
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.Client
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.ClientDeployment
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.AuthorizationConsentRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientDeploymentRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientRepository
import uk.gov.justice.digital.hmpps.authorizationapi.resource.ClientDeploymentDetails
import uk.gov.justice.digital.hmpps.authorizationapi.utils.OAuthClientSecret
import java.time.LocalDateTime
import java.util.Base64.getEncoder

@Service
class RotateClientsService(
  private val clientRepository: ClientRepository,
  private val clientConfigRepository: ClientConfigRepository,
  private val authorizationConsentRepository: AuthorizationConsentRepository,
  private val clientIdService: ClientIdService,
  private val clientDeploymentRepository: ClientDeploymentRepository,
  private val oAuthClientSecret: OAuthClientSecret,
) {

  @Transactional
  fun deleteClient(clientId: String) {
    val clientsByBaseClientId = clientIdService.findByBaseClientId(clientId)
    if (clientsByBaseClientId.isEmpty()) {
      throw ClientNotFoundException(Client::class.simpleName, clientId)
    }

    if (clientsByBaseClientId.size == 1) {
      val baseClientId = clientIdService.toBase(clientId)
      clientDeploymentRepository.deleteByBaseClientId(baseClientId)
      clientConfigRepository.deleteByBaseClientId(baseClientId)
    }

    authorizationConsentRepository.deleteByPrincipalName(clientId)
    clientRepository.deleteByClientId(clientId)
  }

  @Transactional
  fun duplicate(clientId: String): DuplicateRegistrationResponse {
    val clientsByBaseClientId = clientIdService.findByBaseClientId(clientId)
    if (clientsByBaseClientId.isEmpty()) {
      throw ClientNotFoundException(Client::class.simpleName, clientId)
    }

    val client = clientsByBaseClientId.last()

    val externalClientSecret = oAuthClientSecret.generate()

    val duplicatedRegisteredClient = client.copy(
      id = java.util.UUID.randomUUID().toString(),
      clientId = clientIdService.incrementClientId(client.clientId),
      clientIdIssuedAt = LocalDateTime.now(),
      clientSecret = oAuthClientSecret.encode(externalClientSecret),
    )

    clientRepository.save(duplicatedRegisteredClient)
    val authorizationConsent = authorizationConsentRepository.findByIdOrNull(AuthorizationConsentId(client.id, client.clientId))
    authorizationConsent?.let {
      authorizationConsentRepository.save(AuthorizationConsent(duplicatedRegisteredClient.id, duplicatedRegisteredClient.clientId, it.authorities))
    }

    return DuplicateRegistrationResponse(
      duplicatedRegisteredClient.clientId,
      externalClientSecret,
      getEncoder().encodeToString(duplicatedRegisteredClient.clientId.toByteArray()),
      getEncoder().encodeToString(externalClientSecret.toByteArray()),
    )
  }

  @Transactional(readOnly = true)
  fun retrieveClientDeploymentDetails(clientId: String) = getDeployment(clientId)

  private fun getDeployment(clientId: String): ClientDeploymentDetails? {
    val clients = clientIdService.findByBaseClientId(clientId)
    if (clients.isEmpty()) {
      throw ClientNotFoundException(Client::class.simpleName, clientId)
    }

    val baseClientId = clientIdService.toBase(clientId)
    val clientDeployment =
      clientDeploymentRepository.findByIdOrNull(baseClientId)
    return clientDeployment?.let { toClientDeploymentDetails(clientDeployment) }
  }

  private fun toClientDeploymentDetails(clientDeployment: ClientDeployment): ClientDeploymentDetails {
    with(clientDeployment) {
      return ClientDeploymentDetails(
        clientType = clientType?.name,
        team = team,
        teamContact = teamContact,
        teamSlack = teamSlack,
        hosting = hosting?.name,
        namespace = namespace,
        deployment = deployment,
        secretName = secretName,
        clientIdKey = clientIdKey,
        secretKey = secretKey,
        deploymentInfo = deploymentInfo,
      )
    }
  }
}

class ClientNotFoundException(entityName: String?, clientId: String) : RuntimeException("$entityName for client id $clientId not found")

class ClientAlreadyExistsException(clientId: String) : RuntimeException("Client with client id $clientId cannot be created as already exists")

data class DuplicateRegistrationResponse(
  val clientId: String,
  val clientSecret: String,
  val base64ClientId: String,
  val base64ClientSecret: String,
)
