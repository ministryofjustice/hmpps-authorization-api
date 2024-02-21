package uk.gov.justice.digital.hmpps.authorizationserver.resource

import com.microsoft.applicationinsights.TelemetryClient
import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.ResponseStatus
import uk.gov.justice.digital.hmpps.authorizationserver.config.AuthenticationFacade
import uk.gov.justice.digital.hmpps.authorizationserver.config.trackEvent
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.MfaAccess
import uk.gov.justice.digital.hmpps.authorizationserver.service.MigrationClientService
import java.time.Instant
import java.time.LocalDate

@Controller
class MigrationController(
  private val migrationClientService: MigrationClientService,
  private val telemetryClient: TelemetryClient,
  private val authenticationFacade: AuthenticationFacade,
) {

  @PostMapping("migrate-client")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun addClient(
    @Valid @RequestBody
    clientDetails: MigrationClientRequest,
  ) {
    migrationClientService.addClient(clientDetails)
    val telemetryMap = mapOf("username" to authenticationFacade.currentUsername!!, "clientId" to clientDetails.clientId, "grantType" to clientDetails.grantType)
    telemetryClient.trackEvent("AuthorizationServerDetailsMigrate", telemetryMap)
  }

  @GetMapping("all-clients")
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun listAllClientIds(): ResponseEntity<Any> {
    return ResponseEntity.ok(migrationClientService.listAllClientIds())
  }
}

class MigrationClientRequest(
  val clientId: String,
  val scopes: List<String>?,
  val authorities: List<String>?,
  val ips: List<String>?,
  val jiraNumber: String?,
  val databaseUserName: String?,
  val validDays: Long?,
  val accessTokenValidityMinutes: Long?,
  val clientIdIssuedAt: Instant,
  val clientEndDate: LocalDate?,
  var lastAccessed: Instant?,
  val clientSecret: String,
  val grantType: String,
  val clientDeploymentDetails: ClientDeploymentDetails?,
  val jwtFields: String?,
  val mfaRememberMe: Boolean,
  val mfa: MfaAccess?,
  val redirectUris: String?,
)
