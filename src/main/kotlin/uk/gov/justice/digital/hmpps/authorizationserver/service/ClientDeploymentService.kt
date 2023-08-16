package uk.gov.justice.digital.hmpps.authorizationserver.service

import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientDeployment
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientType
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.Hosting
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientDeploymentRepository
import uk.gov.justice.digital.hmpps.authorizationserver.resource.ClientDeploymentDetails

@Service
class ClientDeploymentService(
  private val clientDeploymentRepository: ClientDeploymentRepository,
  private val clientIdService: ClientIdService,
) {

  @Transactional
  fun add(clientId: String, clientDeployment: ClientDeploymentDetails) {
    val baseClientId = clientIdService.toBase(clientId)
    val existingClientDeployment = clientDeploymentRepository.findClientDeploymentByBaseClientId(baseClientId)
    existingClientDeployment?.let {
      throw ClientDeploymentAlreadyExistsException(clientId)
    }

    clientDeploymentRepository.save(toClientDeploymentEntity(clientDeployment, baseClientId))
  }

  @Transactional
  fun update(clientId: String, clientDeployment: ClientDeploymentDetails) {
    val baseClientId = clientIdService.toBase(clientId)
    val existingClientDeployment =
      clientDeploymentRepository.findById(baseClientId)
    if (existingClientDeployment.isEmpty) {
      throw ClientNotFoundException(ClientDeployment::class.simpleName, baseClientId)
    }
    clientDeploymentRepository.save(toClientDeploymentEntity(clientDeployment, baseClientId))
  }

  @Transactional
  fun getDeployment(clientId: String): ClientDeploymentDetails {
    val baseClientId = clientIdService.toBase(clientId)
    val clientDeployment =
      clientDeploymentRepository.findById(baseClientId)
    if (clientDeployment.isEmpty) {
      throw ClientNotFoundException(ClientDeployment::class.simpleName, baseClientId)
    }
    return toClientDeploymentDetails(clientDeployment.get())
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
  private fun toClientDeploymentEntity(clientDeployment: ClientDeploymentDetails, baseClientId: String): ClientDeployment {
    with(clientDeployment) {
      return ClientDeployment(
        baseClientId = baseClientId,
        clientType = clientType?.let { ClientType.valueOf(clientType) },
        team = team,
        teamContact = teamContact,
        teamSlack = teamSlack,
        hosting = hosting?.let { Hosting.valueOf(hosting) },
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

class ClientDeploymentAlreadyExistsException(clientId: String) : RuntimeException("ClientDeployment for client id $clientId already exists")
