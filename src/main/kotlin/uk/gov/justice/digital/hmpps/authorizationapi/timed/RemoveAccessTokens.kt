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
  fun removeAllButLatestAccessToken() {
    try {
      val numberOfRecordsDeleted = service.removeAllButLatestAccessToken()
      log.trace("Authorization API client,{} all but latest access tokens are removed", numberOfRecordsDeleted)

      telemetryClient.trackEvent("AuthorizationApiAccessTokensRemoved", null, null)
    } catch (e: Exception) {
      // have to catch the exception here otherwise scheduling will stop
      log.error("Caught exception {} during removal of all but latest access tokens", e.javaClass.simpleName, e)
    }
  }

  @Scheduled(cron = "\${application.authentication.ac-token.cron}", zone = "Europe/London")
  fun removeAllAuthorizationCodeRecordsWithoutAccessTokens() {
    try {
      val numberOfRecordsDeleted = service.removeAuthCodeAccessTokens()
      log.trace("Authorization API,{} records removed without access tokens", numberOfRecordsDeleted)

      telemetryClient.trackEvent("AuthorizationApiAccessTokensRemoved", null, null)
    } catch (e: Exception) {
      // have to catch the exception here otherwise scheduling will stop
      log.error("Caught exception {} during access token removal", e.javaClass.simpleName, e)
    }
  }

  @Scheduled(cron = "\${application.authentication.user-token.cron}", zone = "Europe/London")
  fun removeRecordsOlderThan20Minutes() {
    try {
      val numberOfRecordsDeleted = service.deleteRecordsOlderThan20Minutes()
      log.trace("Authorization API, {} records older than 20 minutes from table:oauth2_user_authorization_code removed", numberOfRecordsDeleted)

      telemetryClient.trackEvent("AuthorizationApiUserAccessTokensRemoved", null, null)
    } catch (e: Exception) {
      // have to catch the exception here otherwise scheduling will stop
      log.error("Caught exception {} during access token removal from oauth2_user_authorization_code", e.javaClass.simpleName, e)
    }
  }

  companion object {
    private val log = LoggerFactory.getLogger(this::class.java)
  }
}

@Service
class RemoveAccessTokensService(private val repository: AuthorizationRepository) {
  @Transactional
  fun removeAllButLatestAccessToken() = repository.deleteAllButLatestAccessToken()

  @Transactional
  fun removeAuthCodeAccessTokens() = repository.deleteAllAuthorizationCodeRecordsWithoutAccessTokens()

  @Transactional
  fun deleteRecordsOlderThan20Minutes() = repository.deleteRecordsOlderThan20Minutes()
}
