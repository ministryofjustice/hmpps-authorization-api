package uk.gov.justice.digital.hmpps.authorizationserver.timed

import com.microsoft.applicationinsights.TelemetryClient
import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.AuthorizationRepository
import java.time.LocalDateTime

@Component
class RemoveAccessTokens(private val service: RemoveAccessTokensService, private val telemetryClient: TelemetryClient) {

  @Scheduled(cron = "\${application.authentication.access-token.cron}", zone = "Europe/London")
  fun removeExpiredAuthCodes() {
    try {
      service.removeAccessTokens()
      log.trace("Authorization server access-tokens Removed")

      telemetryClient.trackEvent("AuthorizationServerAccessTokensRemoved", null, null)
      println("")
    } catch (e: Exception) {
      // have to catch the exception here otherwise scheduling will stop
      log.error("Caught exception {} during access token removal", e.javaClass.simpleName, e)
    }
  }

  companion object {
    private val log = LoggerFactory.getLogger(this::class.java)
  }
}

@Service
class RemoveAccessTokensService(private val repository: AuthorizationRepository) {
  @Transactional
  fun removeAccessTokens() {
    val oneDayAgo = LocalDateTime.now().minusDays(1)
    repository.deleteByAccessTokenExpiresAtBefore(oneDayAgo)
  }
}
