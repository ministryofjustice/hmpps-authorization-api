package uk.gov.justice.digital.hmpps.authorizationapi.adapter

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.WebClientResponseException
import reactor.core.publisher.Mono
import java.util.*

@Suppress("SpringJavaInjectionPointsAutowiringInspection")
@Service
class AuthService(
  @Qualifier("authWebClient") private val webClient: WebClient,
) {

  companion object {
    private val log = LoggerFactory.getLogger(this::class.java)
  }

  fun getService(clientId: String): Optional<ServiceDetails> {
    try {
      val serviceDetails = webClient.get().uri("/api/services/{clientId}", clientId)
        .retrieve()
        .bodyToMono(ServiceDetails::class.java)
        .onErrorResume(WebClientResponseException::class.java) {
          log.error("Error response on attempt to retrieve service details", it)
          Mono.empty()
        }
        .onErrorResume(Exception::class.java) {
          log.error("Failed to retrieve service details", it)
          Mono.empty()
        }
        .block()!!
      return Optional.of(serviceDetails)
    } catch (e: Exception) {
      return Optional.empty()
    }
  }
}

// && it.statusCode.is4xxClientError

data class ServiceDetails(
  val name: String?,
  val description: String?,
  var authorisedRoles: List<String>?,
  val url: String?,
  val enabled: Boolean?,
  val contact: String?,
)
