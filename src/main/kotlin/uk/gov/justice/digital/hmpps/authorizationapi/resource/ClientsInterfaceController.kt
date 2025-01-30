package uk.gov.justice.digital.hmpps.authorizationapi.resource

import com.microsoft.applicationinsights.TelemetryClient
import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import org.springframework.core.convert.ConversionService
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller
import org.springframework.util.StringUtils.hasText
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseStatus
import uk.gov.justice.digital.hmpps.authorizationapi.adapter.ServiceDetails
import uk.gov.justice.digital.hmpps.authorizationapi.config.AuthenticationFacade
import uk.gov.justice.digital.hmpps.authorizationapi.config.trackEvent
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.ClientType
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.MfaAccess
import uk.gov.justice.digital.hmpps.authorizationapi.service.ClientDetail
import uk.gov.justice.digital.hmpps.authorizationapi.service.ClientFilter
import uk.gov.justice.digital.hmpps.authorizationapi.service.ClientIdService
import uk.gov.justice.digital.hmpps.authorizationapi.service.ClientsInterfaceService
import uk.gov.justice.digital.hmpps.authorizationapi.service.SortBy
import java.time.Instant

@Controller
class ClientsInterfaceController(
  private val clientsService: ClientsInterfaceService,
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
    @RequestParam grantType: GrantType? = null,
    @RequestParam clientType: ClientType? = null,
  ): ResponseEntity<Any> = ResponseEntity.ok(AllClientsResponse(clientsService.retrieveAllClients(sort, ClientFilter(grantType = grantType?.name, role = role, clientType = clientType))))

  @PostMapping("base-clients")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun addClient(
    @Valid @RequestBody
    clientDetails: ClientRegistrationRequest,
  ): ResponseEntity<Any> {
    val registrationResponse = clientsService.addClient(clientDetails)
    val telemetryMap = mapOf("username" to authenticationFacade.currentUsername!!, "clientId" to clientDetails.clientId!!, "grantType" to clientDetails.grantType.name)
    telemetryClient.trackEvent("AuthorizationApiDetailsAdd", telemetryMap)
    return ResponseEntity.ok(registrationResponse)
  }

  @GetMapping("base-clients/{baseClientId}/clients")
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun clients(
    @PathVariable baseClientId: String,
  ): ResponseEntity<Any> = ResponseEntity.ok(conversionService.convert(clientsService.findClientWithCopies(baseClientId), ClientDuplicatesResponse::class.java))

  @DeleteMapping("base-clients/{baseClientId}/clients/{clientId}")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun deleteClient(@PathVariable clientId: String) {
    clientsService.deleteClient(clientId)

    val telemetryMap = mapOf("username" to authenticationFacade.currentUsername!!, "clientId" to clientId)
    telemetryClient.trackEvent("AuthorizationApiClientDeleted", telemetryMap)
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
    telemetryClient.trackEvent("AuthorizationApiClientDetailsDuplicated", telemetryMap)
    return ResponseEntity.ok(duplicateRegistrationResponse)
  }

  @PutMapping("/base-clients/{baseClientId}")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun editClient(@PathVariable baseClientId: String, @RequestBody clientDetails: ClientUpdateRequest) {
    clientsService.editClient(baseClientId, clientDetails)
    val telemetryMap = mapOf("username" to authenticationFacade.currentUsername!!, "clientId" to baseClientId)
    telemetryClient.trackEvent("AuthorizationApiCredentialsUpdate", telemetryMap)
  }

  @GetMapping("base-clients/{baseClientId}")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun viewClient(@PathVariable baseClientId: String): ResponseEntity<Any> = ResponseEntity.ok(
    conversionService.convert(
      clientsService.retrieveClientFullDetails(baseClientId),
      ClientViewResponse::class.java,
    ),
  )

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
    telemetryClient.trackEvent("AuthorizationApiClientDeploymentDetailsUpsert", telemetryMap)
  }
}

data class ClientExistsResponse(
  val clientId: String,
  val accessTokenValiditySeconds: Long?,
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
  val accessTokenValiditySeconds: Long?,
  val deployment: ClientDeploymentDetails?,
  val jwtFields: String?,
  val mfaRememberMe: Boolean,
  val mfa: MfaAccess?,
  val redirectUris: Set<String>?,
  val grantType: GrantType,
  val service: ServiceDetails?,
  val skipToAzure: Boolean?,
  val resourceIds: List<String>?,
)

data class ClientUpdateRequest(
  val scopes: List<String>,
  val authorities: List<String>?,
  val ips: List<String>,
  val jiraNumber: String?,
  val databaseUserName: String?,
  val validDays: Long?,
  val accessTokenValiditySeconds: Long?,
  val jwtFields: String?,
  val mfaRememberMe: Boolean,
  val mfa: MfaAccess?,
  val redirectUris: String?,
  val skipToAzure: Boolean?,
  val resourceIds: List<String>?,
) {
  fun hasAuthorities() = authorities != null && authorities.isNotEmpty() && hasText(authorities[0])
}

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
  val accessTokenValiditySeconds: Long?,
  val redirectUris: String?,
  val jwtFields: String?,
  val mfaRememberMe: Boolean,
  val skipToAzure: Boolean?,
  val resourceIds: List<String>?,
  val mfa: MfaAccess?,
)

data class ClientRegistrationResponse(
  val clientId: String,
  val clientSecret: String,
  val base64ClientId: String,
  val base64ClientSecret: String,
)

@Suppress("ktlint:standard:enum-entry-name-case")
enum class GrantType {
  client_credentials,
  authorization_code,
}
