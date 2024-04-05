package uk.gov.justice.digital.hmpps.authorizationserver.adapter

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.WebClientResponseException
import reactor.core.publisher.Mono
import org.springframework.stereotype.Service as ServiceAnnotation

@Suppress("SpringJavaInjectionPointsAutowiringInspection")
@ServiceAnnotation
class AuthService(
  @Qualifier("authWebClient") private val webClient: WebClient,
) {

  companion object {
    private val log = LoggerFactory.getLogger(this::class.java)
  }

  fun getService(clientId: String): Service? {
    return webClient.get().uri("/api/services/roles/{clientId}", clientId)
      .retrieve()
      .bodyToMono(Service::class.java)
      .onErrorResume(WebClientResponseException::class.java) {
        log.error("Error response on attempt to retrieve service roles", it)
        Mono.empty()
      }
      .onErrorResume(Exception::class.java) {
        log.error("Failed to retrieve service roles", it)
        Mono.empty()
      }
      .block()!!
  }
}

data class Service(
  val name: String?,
  val description: String?,
  var authorisedRoles: List<String>?,
  val url: String?,
  val enabled: Boolean?,
  val contact: String?,
)
