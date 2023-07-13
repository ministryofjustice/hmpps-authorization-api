package uk.gov.justice.digital.hmpps.authorizationserver.resource

import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.ResponseStatus
import uk.gov.justice.digital.hmpps.authorizationserver.service.AllClientDetails
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

  @GetMapping("clients/client-credentials/{clientId}/view")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun viewClient(@PathVariable clientId: String): ResponseEntity<Any> {
    val allClientDetails = clientService.retrieveAllClientDetails(clientId)
    return ResponseEntity.ok(ClientCredentialsViewResponse.fromAllClientDetails(allClientDetails))
  }
}

data class ClientCredentialsViewResponse(
  val clientId: String,
  val clientName: String,
  val scopes: List<String>,
  val authorities: List<String>,
  val ips: List<String>,
  val jiraNumber: String?,
  val databaseUserName: String?,
  val validDays: Long?,
  val accessTokenValidity: Long?,
) {
  companion object {
    fun fromAllClientDetails(allClientDetails: AllClientDetails): ClientCredentialsViewResponse {
      with(allClientDetails) {
        return ClientCredentialsViewResponse(
          latestClient.clientId,
          latestClient.clientName,
          latestClient.scopes,
          authorizationConsent.authorities,
          clientConfig.ips,
          latestClient.getJiraNumber(),
          latestClient.getDatabaseUserName(),
          clientConfig.validDays,
          latestClient.tokenSettings.accessTokenTimeToLive.toMinutes(),
        )
      }
    }
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
