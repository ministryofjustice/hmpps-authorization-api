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
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseStatus
import uk.gov.justice.digital.hmpps.authorizationserver.config.AuthenticationFacade
import uk.gov.justice.digital.hmpps.authorizationserver.config.trackEvent
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientType
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.MfaAccess
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientDetail
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientFilter
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientIdService
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientsService
import uk.gov.justice.digital.hmpps.authorizationserver.service.SortBy
import java.time.Instant

@Controller
class ClientsController(
  private val clientsService: ClientsService,
  private val conversionService: ConversionService,
  private val telemetryClient: TelemetryClient,
  private val authenticationFacade: AuthenticationFacade,
  private val clientIdService: ClientIdService,
) {

  @GetMapping("base-clients")
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun list(
    @RequestParam(defaultValue = "CLIENT") sort: SortBy,
    @RequestParam role: String? = null,
    @RequestParam grantType: String? = null,
    @RequestParam clientType: ClientType? = null,
  ): ResponseEntity<Any> {
    return ResponseEntity.ok(AllClientsResponse(clientsService.retrieveAllClients(sort, ClientFilter(grantType = grantType, role = role, clientType = clientType))))
  }

  @PostMapping("base-clients")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun addClient(
    @Valid @RequestBody
    clientDetails: ClientRegistrationRequest,
  ): ResponseEntity<Any> {
    val registrationResponse = clientsService.addClient(clientDetails)
    val telemetryMap = mapOf("username" to authenticationFacade.currentUsername!!, "clientId" to clientDetails.clientId!!, "grantType" to clientDetails.grantType.name)
    telemetryClient.trackEvent("AuthorizationServerDetailsAdd", telemetryMap)
    return ResponseEntity.ok(registrationResponse)
  }

  @GetMapping("base-clients/{baseClientId}/clients")
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun clients(
    @PathVariable baseClientId: String,
  ): ResponseEntity<Any> {
    return ResponseEntity.ok(conversionService.convert(clientsService.findClientWithCopies(baseClientId), ClientDuplicatesResponse::class.java))
  }

  @GetMapping("clients/exists/{clientId}")
  @PreAuthorize("hasRole('ROLE_OAUTH_CLIENTS_VIEW')")
  @ResponseStatus(HttpStatus.OK)
  fun findClientByClientId(@PathVariable clientId: String): ResponseEntity<Any> {
    return ResponseEntity.ok(conversionService.convert(clientsService.findClientByClientId(clientId), ClientExistsResponse::class.java))
  }

  @DeleteMapping("base-clients/{baseClientId}/clients/{clientId}")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun deleteClient(@PathVariable clientId: String) {
    clientsService.deleteClient(clientId)

    val telemetryMap = mapOf("username" to authenticationFacade.currentUsername!!, "clientId" to clientId)
    telemetryClient.trackEvent("AuthorizationServerClientDeleted", telemetryMap)
  }

  @PostMapping("base-clients/{baseClientId}/clients")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun duplicate(@PathVariable baseClientId: String): ResponseEntity<Any> {
    val duplicateRegistrationResponse = clientsService.duplicate(baseClientId)
    val telemetryMap = mapOf(
      "username" to authenticationFacade.currentUsername!!,
      "clientId" to duplicateRegistrationResponse.clientId,
    )
    telemetryClient.trackEvent("AuthorizationServerClientDetailsDuplicated", telemetryMap)
    return ResponseEntity.ok(duplicateRegistrationResponse)
  }

  @PutMapping("/base-clients/{baseClientId}")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun editClient(@PathVariable baseClientId: String, @RequestBody clientDetails: ClientUpdateRequest) {
    clientsService.editClient(baseClientId, clientDetails)
    val telemetryMap = mapOf("username" to authenticationFacade.currentUsername!!, "clientId" to baseClientId)
    telemetryClient.trackEvent("AuthorizationServerCredentialsUpdate", telemetryMap)
  }

  @GetMapping("base-clients/{baseClientId}")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun viewClient(@PathVariable baseClientId: String): ResponseEntity<Any> {
    return ResponseEntity.ok(
      conversionService.convert(
        clientsService.retrieveClientFullDetails(baseClientId),
        ClientViewResponse::class.java,
      ),
    )
  }

  @PutMapping("base-clients/{baseClientID}/deployment")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun upsertDeployment(
    @PathVariable
    baseClientID: String,
    @RequestBody clientDeployment: ClientDeploymentDetails,
  ) {
    clientsService.upsert(baseClientID, clientDeployment)
    val telemetryMap = mapOf(
      "username" to authenticationFacade.currentUsername!!,
      "baseClientId" to clientIdService.toBase(baseClientID),
    )
    telemetryClient.trackEvent("AuthorizationServerClientDeploymentDetailsUpsert", telemetryMap)
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

data class ClientViewResponse(
  val clientId: String,
  val scopes: List<String>,
  val authorities: List<String>?,
  val ips: List<String>?,
  val jiraNumber: String?,
  val databaseUserName: String?,
  val validDays: Long?,
  val accessTokenValidityMinutes: Long?,
  val deployment: ClientDeploymentDetails?,
  val jwtFields: String?,
  val mfaRememberMe: Boolean,
  val mfa: MfaAccess?,
  val redirectUris: Set<String>?,
  val grantType: String,
)

data class ClientUpdateRequest(
  val scopes: List<String>,
  val authorities: List<String>,
  val ips: List<String>,
  val jiraNumber: String?,
  val databaseUserName: String?,
  val validDays: Long?,
  val accessTokenValidityMinutes: Long?,
  val jwtFields: String?,
  val mfaRememberMe: Boolean,
  val mfa: MfaAccess?,
  val redirectUris: String?,
)

data class ClientDeploymentDetails(
  val clientType: String?,
  val team: String?,
  val teamContact: String?,
  val teamSlack: String?,
  val hosting: String?,
  val namespace: String?,
  val deployment: String?,
  val secretName: String?,
  val clientIdKey: String?,
  val secretKey: String?,
  val deploymentInfo: String?,
)

data class ClientRegistrationRequest(
  @field:NotBlank(message = "clientId must not be blank")
  @field:Size(max = 100, message = "clientId max size is 100")
  val clientId: String?,
  val grantType: GrantType,
  val scopes: List<String>?,
  val authorities: List<String>?,
  val ips: List<String>?,
  val jiraNumber: String?,
  val databaseUserName: String?,
  val validDays: Long?,
  val accessTokenValidityMinutes: Long?,
  val redirectUris: String?,
  val jwtFields: String?,
  val mfaRememberMe: Boolean,
  val mfa: MfaAccess?,
)

data class ClientRegistrationResponse(
  val clientId: String,
  val clientSecret: String,
  val base64ClientId: String,
  val base64ClientSecret: String,
)

enum class GrantType(val description: String) {
  CLIENT_CREDENTIALS("client_credentials"),
  AUTHORIZATION_CODE("authorization_code"),
}
