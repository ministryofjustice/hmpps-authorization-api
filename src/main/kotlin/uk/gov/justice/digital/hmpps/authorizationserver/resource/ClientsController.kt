package uk.gov.justice.digital.hmpps.authorizationserver.resource

import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.ResponseStatus
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientService

@Controller
class ClientsController(
  private val clientService: ClientService,
) {

  @PostMapping("clients/client-credentials/add")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun addClient(@RequestBody clientDetails: ClientCredentialsRegistrationRequest): ResponseEntity<Any> {
    return ResponseEntity.ok(clientService.addClientCredentials(clientDetails))
  }

  @PutMapping("clients/client-credentials/{clientId}/update")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun editClient(@PathVariable clientId: String, @RequestBody clientDetails: ClientCredentialsUpdateRequest) {
    clientService.editClientCredentials(clientId, clientDetails)
  }
}

data class ClientCredentialsUpdateRequest(
  val scopes: List<String>,
  val authorities: List<String>,
  val ips: List<String>,
  val jiraNumber: String?,
  val databaseUserName: String?,
  val validDays: Long?,
  val accessTokenValidity: Long?,
)

data class ClientCredentialsRegistrationRequest(
  val clientId: String,
  val clientName: String,
  val scopes: List<String>,
  val authorities: List<String>,
  val ips: List<String>,
  val jiraNumber: String?,
  val databaseUserName: String?,
  val validDays: Long?,
  val accessTokenValidity: Long?,
)

data class ClientCredentialsRegistrationResponse(
  val clientId: String,
  val clientSecret: String,
)
