package uk.gov.justice.digital.hmpps.authorizationserver.resource

import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientSummary
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientsService

@Controller
class ClientsController(
  private val clientsService: ClientsService,
) {

  @GetMapping("clients/all")
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun list(): ResponseEntity<Any> {
    return ResponseEntity.ok(AllClientsResponse(clientsService.retrieveAllClients()))
  }
}

data class AllClientsResponse(
  val clients: List<ClientSummary>,
)
