package uk.gov.justice.digital.hmpps.authorizationapi.timed

import com.microsoft.applicationinsights.TelemetryClient
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock
import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.AuthorizationRepository

@Component
class RemoveAccessTokens(private val service: RemoveAccessTokensService, private val telemetryClient: TelemetryClient) {

  @Scheduled(cron = "\${application.authentication.cron.remove-access-tokens}", zone = "Europe/London")
  @SchedulerLock(name = "removeAllButLatestAccessToken")
  fun removeAllButLatestAccessToken() {
    try {
      log.trace("removeAllButLatestAccessToken scheduled task started")
      val numberOfRecordsDeleted = service.removeAllButLatestAccessToken()

      log.trace("removeAllButLatestAccessToken scheduled task removed {} access token records", numberOfRecordsDeleted)

      telemetryClient.trackEvent("AuthorizationApiAllButLatestAccessToken", mapOf("numberOfRecordsDeleted" to numberOfRecordsDeleted.toString()), null)
    } catch (e: Exception) {
      // have to catch the exception here otherwise scheduling will stop
      log.error("Caught exception {} during removal of all but latest access tokens", e.javaClass.simpleName, e)
    }
  }

  @Scheduled(cron = "\${application.authentication.cron.remove-expired-auth-codes}", zone = "Europe/London")
  @SchedulerLock(name = "removeAllExpiredAuthorizationCodeRecordsWithoutAccessTokens")
  fun removeAllExpiredAuthorizationCodeRecordsWithoutAccessTokens() {
    try {
      log.trace("removeAllExpiredAuthorizationCodeRecordsWithoutAccessTokens scheduled task started")
      val numberOfRecordsDeleted = service.removeAllExpiredAuthorizationCodeRecordsWithoutAccessTokens()

      log.trace("removeAllExpiredAuthorizationCodeRecordsWithoutAccessTokens scheduled task removed {} expired authorisation code records without access tokens", numberOfRecordsDeleted)
      telemetryClient.trackEvent("AuthorizationApiAllExpiredAuthCodeRecordsWithoutAccessTokens", mapOf("numberOfRecordsDeleted" to numberOfRecordsDeleted.toString()), null)
    } catch (e: Exception) {
      // have to catch the exception here otherwise scheduling will stop
      log.error("Caught exception {} during access token removal", e.javaClass.simpleName, e)
    }
  }

  @Scheduled(cron = "\${application.authentication.cron.remove-expired-user-details}", zone = "Europe/London")
  @SchedulerLock(name = "removeExpiredAuthorizationCodeUsers")
  fun removeExpiredAuthorizationCodeUsers() {
    try {
      log.trace("removeExpiredAuthorizationCodeUsers scheduled task started")
      val numberOfRecordsDeleted = service.deleteExpiredAuthorizationCodeUsers()

      log.trace("removeExpiredAuthorizationCodeUsers scheduled task removed {} expired authorisation code user records", numberOfRecordsDeleted)

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
