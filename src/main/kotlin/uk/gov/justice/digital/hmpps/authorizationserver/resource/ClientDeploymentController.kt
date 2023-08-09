package uk.gov.justice.digital.hmpps.authorizationserver.resource

import com.microsoft.applicationinsights.TelemetryClient
import org.springframework.http.HttpStatus
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.ResponseStatus
import uk.gov.justice.digital.hmpps.authorizationserver.config.AuthenticationFacade
import uk.gov.justice.digital.hmpps.authorizationserver.config.trackEvent
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientDeploymentService
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientIdService

@Controller
class ClientDeploymentController(
  private val clientDeploymentService: ClientDeploymentService,
  private val telemetryClient: TelemetryClient,
  private val authenticationFacade: AuthenticationFacade,
  private val clientIdService: ClientIdService,
) {

  @PostMapping("clients/deployment/add")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun addDeployment(@RequestBody clientDeployment: ClientDeploymentDetailsRequest) {
    clientDeploymentService.add(clientDeployment)
    val telemetryMap = mapOf(
      "username" to authenticationFacade.currentUsername!!,
      "baseClientId" to clientIdService.toBase(clientDeployment.clientId),
    )
    telemetryClient.trackEvent("AuthorizationServerClientDeploymentDetailsAdded", telemetryMap)
  }

  @PutMapping("clients/deployment/{clientId}")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun updateDeployment(
    @PathVariable
    clientId: String,
    @RequestBody clientDeployment: ClientDeploymentDetailsRequest,
  ) {
    clientDeploymentService.update(clientId, clientDeployment)
    val telemetryMap = mapOf(
      "username" to authenticationFacade.currentUsername!!,
      "baseClientId" to clientIdService.toBase(clientDeployment.clientId),
    )
    telemetryClient.trackEvent("AuthorizationServerClientDeploymentDetailsUpdated", telemetryMap)
  }
}

data class ClientDeploymentDetailsRequest(
  val clientId: String,
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
