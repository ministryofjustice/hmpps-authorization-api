package uk.gov.justice.digital.hmpps.authorizationapi.resource

import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.MfaAccess
import uk.gov.justice.digital.hmpps.authorizationapi.service.ClientDataService

@Controller
class ClientsDataController(
  private val clientDataService: ClientDataService,
) {

  @GetMapping("client-details")
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun listClientDetails(): ResponseEntity<Any> {
    return ResponseEntity.ok(clientDataService.fetchClientDetails())
  }
}

data class ClientDetailsResponse(
  val clientId: String,
  val mfaRememberMe: Boolean,
  val mfa: MfaAccess?,
  val scopes: List<String>?,
  val authorities: List<String>?,
  val skipToAzure: Boolean?,
  val ips: List<String>?,
)
