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
    if (!isTokenRequestEvent(successEvent)) return
    val clientId = extractClientIdFrom(successEvent)
    val client = clientRepository.findClientByClientId(clientId)
    if (client == null) {
      log.warn("Client $clientId not found")
    } else {
      if (client.lastAccessedDate == null || client.lastAccessedDate!!.isBeforeToday()) {
        client.lastAccessedDate = LocalDateTime.now()
      }
    }
  }

  fun LocalDateTime.isBeforeToday() = this.toLocalDate().isBefore(LocalDate.now())

  fun isTokenRequestEvent(event: AuthenticationSuccessEvent): Boolean {
    val eventSource = event.source
    return (eventSource is OAuth2AccessTokenAuthenticationToken && eventSource.principal is OAuth2ClientAuthenticationToken) ||
      event.source is OAuth2AuthorizationCodeRequestAuthenticationToken
  }

  private fun extractClientIdFrom(successEvent: AuthenticationSuccessEvent): String = when (val eventSource = successEvent.source) {
    is OAuth2AccessTokenAuthenticationToken -> (eventSource.principal as OAuth2ClientAuthenticationToken).principal.toString()
    is OAuth2AuthorizationCodeRequestAuthenticationToken -> eventSource.clientId
    else -> "unknown"
  }

  companion object {
    private val log = LoggerFactory.getLogger(this::class.java)
  }
}
