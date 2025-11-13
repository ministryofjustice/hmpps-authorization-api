package uk.gov.justice.digital.hmpps.authorizationapi.resource

import com.microsoft.applicationinsights.TelemetryClient
import org.springframework.core.convert.ConversionService
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.ResponseStatus
import uk.gov.justice.digital.hmpps.authorizationapi.config.AuthenticationFacade
import uk.gov.justice.digital.hmpps.authorizationapi.config.trackEvent
import uk.gov.justice.digital.hmpps.authorizationapi.service.ClientsInterfaceService

@Controller
class RotateClientsController(
  private val clientsService: ClientsInterfaceService,
  private val conversionService: ConversionService,
  private val telemetryClient: TelemetryClient,
  private val authenticationFacade: AuthenticationFacade,
) {

  @GetMapping("rotate/base-clients/{baseClientId}/deployment")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_CLIENT_ROTATION_ADMIN')")
  fun viewClientDeployment(@PathVariable baseClientId: String): ResponseEntity<Any> = ResponseEntity.ok(
    conversionService.convert(
      clientsService.retrieveClientDeploymentDetails(baseClientId),
      ClientDeploymentViewResponse::class.java,
    ),
  )

  @PostMapping("rotate/base-clients/{baseClientId}/clients")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_CLIENT_ROTATION_ADMIN')")
  fun duplicate(@PathVariable baseClientId: String): ResponseEntity<Any> {
    val duplicateRegistrationResponse = clientsService.duplicate(baseClientId)
    val telemetryMap = mapOf(
      "username" to authenticationFacade.currentUsername!!,
      "clientId" to duplicateRegistrationResponse.clientId,
    )
    telemetryClient.trackEvent("AuthorizationApiClientDetailsDuplicated", telemetryMap)
    return ResponseEntity.ok(duplicateRegistrationResponse)
  }

  @DeleteMapping("rotate/base-clients/{baseClientId}/clients/{clientId}")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_CLIENT_ROTATION_ADMIN')")
  fun deleteClient(@PathVariable clientId: String) {
    clientsService.deleteClient(clientId)

    val telemetryMap = mapOf("username" to authenticationFacade.currentUsername!!, "clientId" to clientId)
    telemetryClient.trackEvent("AuthorizationApiClientDeleted", telemetryMap)
  }
}
