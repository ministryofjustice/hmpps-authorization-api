package uk.gov.justice.digital.hmpps.authorizationapi.resource

import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.MfaAccess
import uk.gov.justice.digital.hmpps.authorizationapi.service.ClientDataService
import java.time.LocalDateTime

@Controller
class ClientsDataController(
  private val clientDataService: ClientDataService,
) {

  @GetMapping("client-details")
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun listClientDetails(): ResponseEntity<Any> {
    return ResponseEntity.ok(clientDataService.fetchClientDetails())
  }

  @GetMapping("client-details-last-accessed")
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun getAllClientsAndLastAccessed(): ResponseEntity<Any> {
    return ResponseEntity.ok(clientDataService.getAllClientsWithLastAccessed())
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
  val expired: Boolean,
  val redirectUris: List<String>?,
)

data class ClientLastAccessedResponse(val clientId: String, val lastAccessed: LocalDateTime, val pod: String)
