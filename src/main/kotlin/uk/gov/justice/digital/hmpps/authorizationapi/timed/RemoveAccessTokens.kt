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

  @Scheduled(cron = "\${application.authentication.cron.remove-access-tokens}", zone = "Europe/London")
  fun removeAllButLatestAccessToken() {
    try {
      val numberOfRecordsDeleted = service.removeAllButLatestAccessToken()

      log.trace("Authorization API removed {} access token records", numberOfRecordsDeleted)

      telemetryClient.trackEvent("AuthorizationApiAllButLatestAccessToken", mapOf("numberOfRecordsDeleted" to numberOfRecordsDeleted.toString()), null)
    } catch (e: Exception) {
      // have to catch the exception here otherwise scheduling will stop
      log.error("Caught exception {} during removal of all but latest access tokens", e.javaClass.simpleName, e)
    }
  }

  @Scheduled(cron = "\${application.authentication.cron.remove-expired-auth-codes}", zone = "Europe/London")
  fun removeAllExpiredAuthorizationCodeRecordsWithoutAccessTokens() {
    try {
      val numberOfRecordsDeleted = service.removeAllExpiredAuthorizationCodeRecordsWithoutAccessTokens()

      log.trace("Authorization API removed {} expired authorisation code records without access tokens", numberOfRecordsDeleted)
      telemetryClient.trackEvent("AuthorizationApiAllExpiredAuthCodeRecordsWithoutAccessTokens", mapOf("numberOfRecordsDeleted" to numberOfRecordsDeleted.toString()), null)
    } catch (e: Exception) {
      // have to catch the exception here otherwise scheduling will stop
      log.error("Caught exception {} during access token removal", e.javaClass.simpleName, e)
    }
  }

  @Scheduled(cron = "\${application.authentication.cron.remove-expired-user-details}", zone = "Europe/London")
  fun removeExpiredAuthorizationCodeUsers() {
    try {
      val numberOfRecordsDeleted = service.deleteExpiredAuthorizationCodeUsers()

      log.trace("Authorization API removed {} expired authorisation code user records", numberOfRecordsDeleted)

      telemetryClient.trackEvent("AuthorizationApiExpiredAuthCodeUsers", mapOf("numberOfRecordsDeleted" to numberOfRecordsDeleted.toString()), null)
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
@Transactional
class RemoveAccessTokensService(private val repository: AuthorizationRepository) {
  fun removeAllButLatestAccessToken() = repository.deleteAllButLatestAccessToken()

  fun removeAllExpiredAuthorizationCodeRecordsWithoutAccessTokens() = repository.deleteAllExpiredAuthorizationCodeRecordsWithoutAccessTokens()

  fun deleteExpiredAuthorizationCodeUsers() = repository.deleteExpiredAuthorizationCodeUsers()
}
