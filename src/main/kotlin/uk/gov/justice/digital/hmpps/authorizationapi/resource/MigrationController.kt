package uk.gov.justice.digital.hmpps.authorizationapi.resource

import com.microsoft.applicationinsights.TelemetryClient
import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller
import org.springframework.util.StringUtils.hasText
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.ResponseStatus
import uk.gov.justice.digital.hmpps.authorizationapi.config.AuthenticationFacade
import uk.gov.justice.digital.hmpps.authorizationapi.config.trackEvent
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.MfaAccess
import uk.gov.justice.digital.hmpps.authorizationapi.service.MigrateClientService
import java.time.LocalDate
import java.time.LocalDateTime

@Controller
class MigrationController(
  private val migrationClientService: MigrateClientService,
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
    migrationClientService.addUpdateClient(clientDetails)
    val telemetryMap = mapOf("username" to authenticationFacade.currentUsername!!, "clientId" to clientDetails.clientId, "grantType" to clientDetails.grantType)
    telemetryClient.trackEvent("AuthorizationApiDetailsMigrate", telemetryMap)
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
  val accessTokenValiditySeconds: Long?,
  val clientIdIssuedAt: LocalDateTime,
  val clientEndDate: LocalDate?,
  var lastAccessed: LocalDateTime?,
  val clientSecret: String,
  val grantType: String,
  val clientDeploymentDetails: ClientDeploymentDetails?,
  val jwtFields: String?,
  val mfaRememberMe: Boolean,
  val mfa: MfaAccess?,
  val redirectUris: String?,
  val skipToAzureField: Boolean?,
  val resourceIds: List<String>?,
) {

  fun requiresAuthorisationConsentRecord(): Boolean = GrantType.client_credentials.name == grantType && hasAuthorities()

  private fun hasAuthorities() = authorities != null && authorities.isNotEmpty() && hasText(authorities[0])
}
