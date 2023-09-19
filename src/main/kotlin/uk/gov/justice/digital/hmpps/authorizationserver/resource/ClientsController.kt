package uk.gov.justice.digital.hmpps.authorizationserver.resource

import com.microsoft.applicationinsights.TelemetryClient
import org.springframework.core.convert.ConversionService
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseStatus
import uk.gov.justice.digital.hmpps.authorizationserver.config.AuthenticationFacade
import uk.gov.justice.digital.hmpps.authorizationserver.config.trackEvent
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientType
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientDetail
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientFilter
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientsService
import uk.gov.justice.digital.hmpps.authorizationserver.service.SortBy
import java.time.Instant

@Controller
class ClientsController(
  private val clientsService: ClientsService,
  private val conversionService: ConversionService,
  private val telemetryClient: TelemetryClient,
  private val authenticationFacade: AuthenticationFacade,
) {

  @GetMapping("clients/all")
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun list(
    @RequestParam(defaultValue = "CLIENT") sort: SortBy,
    @RequestParam role: String? = null,
    @RequestParam grantType: String? = null,
    @RequestParam clientType: ClientType? = null,
  ): ResponseEntity<Any> {
    return ResponseEntity.ok(AllClientsResponse(clientsService.retrieveAllClients(sort, ClientFilter(grantType = grantType, role = role, clientType = clientType))))
  }

  @GetMapping("clients/duplicates/{clientId}")
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun clients(
    @PathVariable clientId: String,
  ): ResponseEntity<Any> {
    return ResponseEntity.ok(conversionService.convert(clientsService.findClientWithCopies(clientId), ClientDuplicatesResponse::class.java))
  }

  @GetMapping("clients/exists/{clientId}")
  @PreAuthorize("hasRole('ROLE_OAUTH_CLIENTS_VIEW')")
  @ResponseStatus(HttpStatus.OK)
  fun findClientByClientId(@PathVariable clientId: String): ResponseEntity<Any> {
    return ResponseEntity.ok(conversionService.convert(clientsService.findClientByClientId(clientId), ClientExistsResponse::class.java))
  }

  @DeleteMapping("clients/{clientId}/delete")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun deleteClient(@PathVariable clientId: String) {
    clientsService.deleteClient(clientId)

    val telemetryMap = mapOf("username" to authenticationFacade.currentUsername!!, "clientId" to clientId)
    telemetryClient.trackEvent("AuthorizationServerClientDeleted", telemetryMap)
  }

  @PostMapping("clients/{clientId}/duplicate")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun duplicate(@PathVariable clientId: String): ResponseEntity<Any> {
    val duplicateRegistrationResponse = clientsService.duplicate(clientId)
    val telemetryMap = mapOf(
      "username" to authenticationFacade.currentUsername!!,
      "clientId" to duplicateRegistrationResponse.clientId,
    )
    telemetryClient.trackEvent("AuthorizationServerClientDetailsDuplicated", telemetryMap)
    return ResponseEntity.ok(duplicateRegistrationResponse)
  }
}

data class ClientExistsResponse(
  val clientId: String,
  val accessTokenValidityMinutes: Long?,
)

data class ClientDateSummary(
  val clientId: String,
  val created: Instant,
  val lastAccessed: Instant?,
)

data class ClientDuplicatesResponse(
  val clients: List<ClientDateSummary>,
  val grantType: GrantType,
)

data class AllClientsResponse(
  val clients: List<ClientDetail>,
)

enum class GrantType {
  CLIENT_CREDENTIALS,
  AUTHORIZATION_CODE,
}
