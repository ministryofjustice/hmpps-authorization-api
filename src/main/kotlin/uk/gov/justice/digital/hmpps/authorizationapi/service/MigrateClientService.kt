package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.springframework.core.convert.ConversionService
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.AuthorizationConsent
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.Client
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.ClientConfig
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.AuthorizationConsentRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientRepository
import uk.gov.justice.digital.hmpps.authorizationapi.resource.ClientUpdateRequest
import uk.gov.justice.digital.hmpps.authorizationapi.resource.MigrationClientRequest
import java.time.LocalDate

@Service
class MigrateClientService(
  private val clientRepository: ClientRepository,
  private val clientConfigRepository: ClientConfigRepository,
  private val authorizationConsentRepository: AuthorizationConsentRepository,
  private val clientIdService: ClientIdService,
  private val conversionService: ConversionService,
  private val clientsService: ClientsInterfaceService,
) {

  @Transactional
  fun addUpdateClient(migrationClientRequest: MigrationClientRequest) {
    val existingClient = clientRepository.findClientByClientId(migrationClientRequest.clientId)

    val client = conversionService.convert(migrationClientRequest, Client::class.java)

    if (existingClient != null) updateMigratedClient(migrationClientRequest) else client?.let { saveClient(it, migrationClientRequest) }
  }

  private fun updateMigratedClient(migrationClientRequest: MigrationClientRequest) {
    clientsService.editClient(
      migrationClientRequest.clientId,
      mapToClientDetails(migrationClientRequest),
    )
    migrationClientRequest.clientDeploymentDetails?.let { clientsService.upsert(migrationClientRequest.clientId, it) }
  }

  private fun saveClient(client: Client, migrationClientRequest: MigrationClientRequest) {
    client.let { clientRepository.save(it) }

    if (migrationClientRequest.requiresAuthorisationConsentRecord()) {
      authorizationConsentRepository.save(
        AuthorizationConsent(
          client.id,
          client.clientId,
          (withAuthoritiesPrefix(migrationClientRequest.authorities!!)),
        ),
      )
    }

    migrationClientRequest.ips?.let { ips ->
      clientConfigRepository.save(ClientConfig(clientIdService.toBase(client.clientId), ips, getClientEndDate(migrationClientRequest.validDays)))
    }
    migrationClientRequest.clientDeploymentDetails?.let { clientsService.saveClientDeploymentDetails(migrationClientRequest.clientId, it) }
  }

  private fun withAuthoritiesPrefix(authorities: List<String>) = authorities
    .map { it.trim().uppercase() }
    .map { if (it.startsWith("ROLE_")) it else "ROLE_$it" }

  private fun getClientEndDate(validDays: Long?): LocalDate? = validDays?.let {
    val validDaysIncludeToday = it.minus(1)
    LocalDate.now().plusDays(validDaysIncludeToday)
  }

  private fun mapToClientDetails(migrationClientRequest: MigrationClientRequest) = with(migrationClientRequest) {
    ClientUpdateRequest(
      scopes = scopes ?: emptyList(),
      authorities = authorities ?: emptyList(),
      jiraNumber = jiraNumber,
      databaseUserName = databaseUserName,
      accessTokenValiditySeconds = accessTokenValiditySeconds,
      jwtFields = jwtFields,
      mfaRememberMe = mfaRememberMe,
      mfa = mfa,
      redirectUris = redirectUris,
      skipToAzure = skipToAzureField,
      resourceIds = resourceIds,
      ips = ips ?: emptyList(),
      validDays = validDays,
    )
  }
}
