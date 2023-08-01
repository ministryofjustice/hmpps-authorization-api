@file:Suppress("DEPRECATION")

package uk.gov.justice.digital.hmpps.authorizationserver.service

import org.springframework.stereotype.Service
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.AuthorizationConsent
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientConfig
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientDeployment
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientType
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.AuthorizationConsentRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientDeploymentRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientRepository
import uk.gov.justice.digital.hmpps.authorizationserver.service.SortBy.count
import uk.gov.justice.digital.hmpps.authorizationserver.service.SortBy.lastAccessed
import uk.gov.justice.digital.hmpps.authorizationserver.service.SortBy.secretUpdated
import uk.gov.justice.digital.hmpps.authorizationserver.service.SortBy.team
import uk.gov.justice.digital.hmpps.authorizationserver.service.SortBy.type
import uk.gov.justice.digital.hmpps.authorizationserver.utils.ClientIdConverter
import java.time.LocalDate
import java.time.LocalDateTime

@Service
class ClientsService(
  private val clientRepository: ClientRepository,
  private val clientConfigRepository: ClientConfigRepository,
  private val authorizationConsentRepository: AuthorizationConsentRepository,
  private val clientIdConverter: ClientIdConverter,
  private val clientDeploymentRepository: ClientDeploymentRepository,
) {
  fun retrieveAllClients(sortBy: SortBy, filterBy: ClientFilter?): List<ClientSummary> {
    val baseClients = clientRepository.findAll().groupBy { clientIdConverter.toBase(it.clientId) }.toSortedMap()
    val configs = clientConfigRepository.findAll().associateBy { it.baseClientId }
    val deployments = clientDeploymentRepository.findAll().associateBy { it.baseClientId }
    val authorizationConsents =
      authorizationConsentRepository.findAll().associateBy { clientIdConverter.toBase(it.principalName) }

    return baseClients.toList().map { client ->
      val config: ClientConfig? = configs[client.first]
      val deployment: ClientDeployment? = deployments[client.first]
      val authorities: AuthorizationConsent? = authorizationConsents[client.first]
      val firstClient = client.second[0]
      val roles = authorities?.authoritiesWithoutPrefix?.sorted()?.joinToString("\n")
      val lastAccessed = client.second.map { it.lastAccessed }.maxOrNull()
      val secretUpdated = client.second.map { it.secretUpdated }.maxOrNull()
      ClientSummary(
        baseClientId = client.first,
        clientType = deployment?.clientType,
        teamName = deployment?.team,
        grantType = firstClient.authorizationGrantTypes,
        roles = roles,
        count = client.second.size,
        expired = if (config?.clientEndDate?.isBefore(LocalDate.now()) == true) "EXPIRED" else null,
        secretUpdated = secretUpdated,
        lastAccessed = lastAccessed,
      )
    }.filter { cs ->
      filterBy?.let { filter ->
        (filter.clientType == null || filter.clientType == cs.clientType) &&
          (filter.grantType.isNullOrBlank() || cs.grantType.contains(filter.grantType)) &&
          (filter.role.isNullOrBlank() || cs.roles?.contains(filter.role.uppercase()) ?: false)
      } ?: true
    }
      .sortedWith(
        compareBy {
          when (sortBy) {
            type -> it.clientType
            team -> it.teamName
            count -> it.count
            lastAccessed -> it.lastAccessed
            secretUpdated -> it.secretUpdated
            else -> it.baseClientId
          }
        },
      )
  }
}

enum class SortBy {
  client, type, team, lastAccessed, secretUpdated, count // ktlint-disable enum-entry-name-case
}

data class ClientFilter(
  val grantType: String? = null,
  val role: String? = null,
  val clientType: ClientType? = null,
)

data class ClientSummary(
  val baseClientId: String,
  val clientType: ClientType?,
  val teamName: String?,
  val grantType: String,
  val roles: String?,
  val count: Int,
  val expired: String?,
  val secretUpdated: LocalDateTime?,
  val lastAccessed: LocalDateTime?,

)
