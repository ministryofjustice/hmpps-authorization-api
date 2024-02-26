package uk.gov.justice.digital.hmpps.authorizationserver.service

import org.springframework.core.convert.ConversionService
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.AuthorizationConsent
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.Client
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientConfig
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.AuthorizationConsentRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientRepository
import uk.gov.justice.digital.hmpps.authorizationserver.resource.MigrationClientRequest
import java.time.LocalDate

@Service
class MigrationClientService(
  private val clientRepository: ClientRepository,
  private val clientConfigRepository: ClientConfigRepository,
  private val authorizationConsentRepository: AuthorizationConsentRepository,
  private val clientIdService: ClientIdService,
  private val conversionService: ConversionService,
  private val clientsService: ClientsService,
) {

  @Transactional
  fun addClient(migrationClientRequest: MigrationClientRequest) {
    val clientList = clientIdService.findByBaseClientId(migrationClientRequest.clientId!!)
    if (clientList.isNotEmpty()) {
      throw ClientAlreadyExistsException(migrationClientRequest.clientId)
    }
    var client = conversionService.convert(migrationClientRequest, Client::class.java)

    client = client.let { clientRepository.save(it) }
    migrationClientRequest.authorities?.let { authorities ->
      authorizationConsentRepository.save(AuthorizationConsent(client!!.id!!, client.clientId, (withAuthoritiesPrefix(authorities))))
    }

    migrationClientRequest.ips?.let { ips ->
      clientConfigRepository.save(ClientConfig(clientIdService.toBase(client!!.clientId), ips, getClientEndDate(migrationClientRequest.validDays)))
    }
    migrationClientRequest.clientDeploymentDetails?.let { clientsService.saveClientDeploymentDetails(migrationClientRequest.clientId, it) }
  }

  fun listAllClientIds(): List<String> =
    clientRepository.findAll().map { it.clientId }.toList()

  private fun withAuthoritiesPrefix(authorities: List<String>) =
    authorities
      .map { it.trim().uppercase() }
      .map { if (it.startsWith("ROLE_")) it else "ROLE_$it" }

  private fun getClientEndDate(validDays: Long?): LocalDate? {
    return validDays?.let {
      val validDaysIncludeToday = it.minus(1)
      LocalDate.now().plusDays(validDaysIncludeToday)
    }
  }
}
