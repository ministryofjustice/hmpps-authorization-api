package uk.gov.justice.digital.hmpps.authorizationapi.timed

import com.microsoft.applicationinsights.TelemetryClient
import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.AuthorizationRepository

@Component
class RemoveAccessTokens(private val service: RemoveAccessTokensService, private val telemetryClient: TelemetryClient) {

  @Scheduled(cron = "\${application.authentication.cc-token.cron}", zone = "Europe/London")
  fun removeClientCredentialsAccessToken() {
    try {
      service.removeAccessTokens()
      log.trace("Authorization API client credentials access-tokens removed")

      telemetryClient.trackEvent("AuthorizationApiCCAccessTokensRemoved", null, null)
    } catch (e: Exception) {
      // have to catch the exception here otherwise scheduling will stop
      log.error("Caught exception {} during access token removal", e.javaClass.simpleName, e)
    }
  }

  @Scheduled(cron = "\${application.authentication.ac-token.cron}", zone = "Europe/London")
  fun removeClientAuthorizationCodeAccessToken() {
    try {
      service.removeAuthCodeAccessTokens()
      log.trace("Authorization API authorization-code access-tokens removed")

      telemetryClient.trackEvent("AuthorizationApiACAccessTokensRemoved", null, null)
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
    repository.deleteAllButLatestClientCredentialsAccessToken()
  }

  @Transactional
  fun removeAuthCodeAccessTokens() {
    repository.deleteAllButLatestAuthorizationCodeAccessToken()
  }
}
