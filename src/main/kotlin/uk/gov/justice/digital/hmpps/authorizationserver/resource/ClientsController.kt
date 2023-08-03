package uk.gov.justice.digital.hmpps.authorizationserver.resource

import com.microsoft.applicationinsights.TelemetryClient
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.ResponseStatus
import uk.gov.justice.digital.hmpps.authorizationserver.config.AuthenticationFacade
import uk.gov.justice.digital.hmpps.authorizationserver.config.trackEvent
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientSummary
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientsService

@Controller
class ClientsController(
  private val clientsService: ClientsService,
  private val telemetryClient: TelemetryClient,
  private val authenticationFacade: AuthenticationFacade,
) {

  @GetMapping("clients/all")
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun list(): ResponseEntity<Any> {
    return ResponseEntity.ok(AllClientsResponse(clientsService.retrieveAllClients()))
  }

  @DeleteMapping("clients/{clientId}/delete")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun deleteClient(@PathVariable clientId: String) {
    clientsService.deleteClient(clientId)

    val telemetryMap = mapOf("username" to authenticationFacade.currentUsername!!, "clientId" to clientId)
    telemetryClient.trackEvent("AuthorizationServerClientDeleted", telemetryMap)
  }
}

data class AllClientsResponse(
  val clients: List<ClientSummary>,
)
