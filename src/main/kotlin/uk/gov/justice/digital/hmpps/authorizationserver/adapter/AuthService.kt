package uk.gov.justice.digital.hmpps.authorizationserver.adapter

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.beans.factory.annotation.Value
import org.springframework.core.ParameterizedTypeReference
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.WebClientResponseException
import reactor.core.publisher.Mono

@Suppress("SpringJavaInjectionPointsAutowiringInspection")
@Service
class AuthService(
  @Qualifier("authWebClient") private val webClient: WebClient,
  @Value("\${auth.enabled:false}") private val authEnabled: Boolean,
) {

  companion object {
    private val log = LoggerFactory.getLogger(this::class.java)
  }

  fun getServiceRoles(clientId: String): List<String> {
    return webClient.get().uri("/api/services/roles/{clientId}", clientId)
      .retrieve()
      .bodyToMono(object : ParameterizedTypeReference<List<String>>() {})
      .defaultIfEmpty(emptyList())
      .onErrorResume(WebClientResponseException::class.java) {
        log.error("Error response on attempt to retrieve service roles", it)
        Mono.just(emptyList())
      }
      .onErrorResume(Exception::class.java) {
        log.error("Failed to retrieve service roles", it)
        Mono.just(emptyList())
      }
      .block()!!
  }
}
