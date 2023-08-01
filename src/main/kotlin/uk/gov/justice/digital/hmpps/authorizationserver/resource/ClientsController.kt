package uk.gov.justice.digital.hmpps.authorizationserver.resource

import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientType
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientFilter
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientSummary
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientsService
import uk.gov.justice.digital.hmpps.authorizationserver.service.SortBy

@Controller
class ClientsController(
  private val clientsService: ClientsService,
) {

  @GetMapping("clients/all")
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun list(
    @RequestParam(defaultValue = "client") sort: SortBy,
    @RequestParam role: String? = null,
    @RequestParam grantType: String? = null,
    @RequestParam clientType: ClientType? = null,
  ): ResponseEntity<Any> {
    return ResponseEntity.ok(AllClientsResponse(clientsService.retrieveAllClients(sort, ClientFilter(grantType = grantType, role = role, clientType = clientType))))
  }
}

data class AllClientsResponse(
  val clients: List<ClientSummary>,
)
