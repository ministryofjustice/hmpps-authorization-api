package uk.gov.justice.digital.hmpps.authorizationserver.service

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.stereotype.Component
import java.time.Duration

@Component
class RegisteredClientAdditionalInformation {

  companion object {
    private const val TOKEN_ADDITIONAL_DATA = "settings.token.additional-data."

    const val JIRA_NUMBER_KEY = TOKEN_ADDITIONAL_DATA + "jira-number"
    const val DATABASE_USER_NAME_KEY = TOKEN_ADDITIONAL_DATA + "database-user-name"

    const val CLAIMS_JIRA_NUMBER = "jira_number"
  }

  fun buildTokenSettings(accessTokenValidity: Long?, databaseUserName: String?, jiraNumber: String?): TokenSettings {
    val tokenSettingsBuilder = TokenSettings.builder().idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
    accessTokenValidity?.let {
      tokenSettingsBuilder.accessTokenTimeToLive(Duration.ofMinutes(it))
    }

    databaseUserName?.let {
      tokenSettingsBuilder.settings { it[DATABASE_USER_NAME_KEY] = databaseUserName }
    }

    jiraNumber?.let {
      tokenSettingsBuilder.settings { it[JIRA_NUMBER_KEY] = jiraNumber }
    }

    return tokenSettingsBuilder.build()
  }

  fun getDatabaseUserName(registeredClient: RegisteredClient?): String? {
    return registeredClient?.let {
      it.tokenSettings.settings[DATABASE_USER_NAME_KEY] as String?
    }
  }

  fun mapFrom(claims: Map<String, Any>): Map<String, Any> {
    val additionalTokenSettings = HashMap<String, Any>()
    claims[CLAIMS_JIRA_NUMBER]?.let { additionalTokenSettings[JIRA_NUMBER_KEY] = it }
    return additionalTokenSettings
  }
}
