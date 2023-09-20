package uk.gov.justice.digital.hmpps.authorizationserver.resource

import com.microsoft.applicationinsights.TelemetryClient
import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import org.springframework.core.convert.ConversionService
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
import uk.gov.justice.digital.hmpps.authorizationserver.config.AuthenticationFacade
import uk.gov.justice.digital.hmpps.authorizationserver.config.trackEvent
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientCredentialsService

@Controller
class ClientCredentialsController(
  private val clientService: ClientCredentialsService,
  private val conversionService: ConversionService,
  private val telemetryClient: TelemetryClient,
  private val authenticationFacade: AuthenticationFacade,
) {

  @PostMapping("clients/client-credentials/add")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun addClient(
    @Valid @RequestBody
    clientDetails: ClientCredentialsRegistrationRequest,
  ): ResponseEntity<Any> {
    val registrationResponse = clientService.addClientCredentials(clientDetails)
    val telemetryMap = mapOf("username" to authenticationFacade.currentUsername!!, "clientId" to clientDetails.clientId!!)
    telemetryClient.trackEvent("AuthorizationServerClientCredentialsDetailsAdd", telemetryMap)
    return ResponseEntity.ok(registrationResponse)
  }

  @PutMapping("clients/client-credentials/{clientId}/update")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun editClient(@PathVariable clientId: String, @RequestBody clientDetails: ClientCredentialsUpdateRequest) {
    clientService.editClientCredentials(clientId, clientDetails)
    val telemetryMap = mapOf("username" to authenticationFacade.currentUsername!!, "clientId" to clientId)
    telemetryClient.trackEvent("AuthorizationServerClientCredentialsUpdate", telemetryMap)
  }

  @GetMapping("clients/client-credentials/{clientId}/view")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun viewClient(@PathVariable clientId: String): ResponseEntity<Any> {
    return ResponseEntity.ok(
      conversionService.convert(
        clientService.retrieveClientFullDetails(clientId),
        ClientCredentialsViewResponse::class.java,
      ),
    )
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
  val accessTokenValidityMinutes: Long?,
)

data class ClientCredentialsUpdateRequest(
  val scopes: List<String>,
  val authorities: List<String>,
  val ips: List<String>,
  val jiraNumber: String?,
  val databaseUserName: String?,
  val validDays: Long?,
  val accessTokenValidityMinutes: Long?,
)

data class ClientCredentialsRegistrationRequest(
  @field:NotBlank(message = "clientId must not be blank")
  @field:Size(max = 100, message = "clientId max size is 100")
  val clientId: String?,

  @field:NotBlank(message = "clientName must not be blank")
  @field:Size(max = 100, message = "clientName max size is 200")
  val clientName: String?,

  val scopes: List<String>?,
  val authorities: List<String>?,
  val ips: List<String>?,
  val jiraNumber: String?,
  val databaseUserName: String?,
  val validDays: Long?,
  val accessTokenValidityMinutes: Long?,
)

data class ClientCredentialsRegistrationResponse(
  val clientId: String,
  val clientSecret: String,
)
