package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
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

  fun buildTokenSettings(accessTokenValiditySeconds: Long?): TokenSettings {
    val tokenSettingsBuilder = TokenSettings.builder().idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
    accessTokenValiditySeconds?.let {
      tokenSettingsBuilder.accessTokenTimeToLive(Duration.ofSeconds(it))
    }

    return tokenSettingsBuilder.build()
  }

  fun getDatabaseUserName(tokenSettings: TokenSettings?): String? {
    return tokenSettings?.let { it.settings[DATABASE_USER_NAME_KEY] as String? }
  }

  fun mapFrom(claims: Map<String, Any>): Map<String, Any> {
    val additionalTokenSettings = HashMap<String, Any>()
    claims[CLAIMS_JIRA_NUMBER]?.let { additionalTokenSettings[JIRA_NUMBER_KEY] = it }
    return additionalTokenSettings
  }
}
