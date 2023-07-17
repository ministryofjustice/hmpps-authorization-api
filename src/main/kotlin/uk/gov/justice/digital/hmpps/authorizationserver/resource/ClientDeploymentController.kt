package uk.gov.justice.digital.hmpps.authorizationserver.resource

import org.springframework.http.HttpStatus
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.ResponseStatus
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientDeploymentService

@Controller
class ClientDeploymentController(
  private val clientDeploymentService: ClientDeploymentService,
) {

  @PostMapping("clients/deployment/add")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun addDeployment(@RequestBody clientDeployment: ClientDeploymentDetailsRequest) {
    clientDeploymentService.add(clientDeployment)
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
