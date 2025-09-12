package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.slf4j.LoggerFactory
import org.springframework.context.event.EventListener
import org.springframework.security.authentication.event.AuthenticationSuccessEvent
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.stereotype.Component
import org.springframework.transaction.annotation.Transactional
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientRepository
import java.time.LocalDate
import java.time.LocalDateTime

@Component
class AuthenticationSuccessHandler(
  private val clientRepository: ClientRepository,
) {

  @Transactional
  @EventListener
  fun recordAuthenticationSuccessEvent(successEvent: AuthenticationSuccessEvent) {
    val clientId = extractClientIdFrom(successEvent)
    val client = clientRepository.findClientByClientId(clientId)
    if (client == null) {
      log.warn("Client $clientId not found")
    } else {
      if (client.lastAccessedDate == null) {
        client.lastAccessedDate = LocalDateTime.now()
      } else {
        if (client.lastAccessedDate!!.isBeforeToday()) {
          client.lastAccessedDate = LocalDateTime.now()
        }
      }
    }
  }

  fun LocalDateTime.isBeforeToday(): Boolean {
    val date = this.toLocalDate()
    return date != LocalDate.now() && date.isBefore(LocalDate.now())
  }

  private fun extractClientIdFrom(successEvent: AuthenticationSuccessEvent): String {
    val eventSource = successEvent.source
    return when (eventSource) {
      is OAuth2ClientAuthenticationToken -> eventSource.principal.toString()
      is OAuth2AuthorizationCodeRequestAuthenticationToken -> eventSource.clientId
      is OAuth2AccessTokenAuthenticationToken -> eventSource.principal.toString()
      else -> "unknown"
    }
  }

  companion object {
    private val log = LoggerFactory.getLogger(this::class.java)
  }
}
