package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.springframework.beans.factory.annotation.Value
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.stereotype.Component
import java.time.Duration

@Component
class RegisteredClientAdditionalInformation(
  @Value("\${application.oauth2.authorizationcode.timetolive}") val authorizationCodeTTL: String?,
) {

  companion object {
    private const val CLIENT_ADDITIONAL_DATA = "settings.client.additional-data."
    const val JIRA_NUMBER_KEY = CLIENT_ADDITIONAL_DATA + "jira-number"
    const val DATABASE_USER_NAME_KEY = CLIENT_ADDITIONAL_DATA + "database-user-name"
    const val JWT_FIELDS_NAME_KEY = CLIENT_ADDITIONAL_DATA + "jwtFields"
    const val CLAIMS_JIRA_NUMBER = "jira_number"
    const val AUTH_CODE_TTL_DEFAULT_DURATION = "PT5M"
  }

  fun buildTokenSettings(accessTokenValiditySeconds: Long?): TokenSettings {
    val tokenSettingsBuilder = TokenSettings.builder()
      .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)

    accessTokenValiditySeconds?.let {
      tokenSettingsBuilder.accessTokenTimeToLive(Duration.ofSeconds(it))
    }

    // Spring defaults to 5 minutes if no value is explicitly set. Maintain this behaviour if no override is present
    val authCodeTTLDuration = authorizationCodeTTL?.trim()?.ifEmpty { AUTH_CODE_TTL_DEFAULT_DURATION } ?: AUTH_CODE_TTL_DEFAULT_DURATION
    tokenSettingsBuilder.authorizationCodeTimeToLive(Duration.parse(authCodeTTLDuration))

    return tokenSettingsBuilder.build()
  }

  fun buildClientSettings(databaseUserName: String?, jiraNumber: String?, jwtFields: String?): ClientSettings {
    val clientSettingsBuilder = ClientSettings.builder().requireProofKey(false)
      .requireAuthorizationConsent(false)

    databaseUserName?.let {
      clientSettingsBuilder.settings { it[DATABASE_USER_NAME_KEY] = databaseUserName }
    }

    jiraNumber?.let {
      clientSettingsBuilder.settings { it[JIRA_NUMBER_KEY] = jiraNumber }
    }

    jwtFields?.let {
      clientSettingsBuilder.settings { it[JWT_FIELDS_NAME_KEY] = jwtFields }
    }
    return clientSettingsBuilder.build()
  }

  fun getDatabaseUserName(clientSettings: ClientSettings?): String? {
    return clientSettings?.let { it.settings[DATABASE_USER_NAME_KEY] as String? }
  }

  fun getJiraNumber(clientSettings: ClientSettings?): String? {
    return clientSettings?.let { it.settings[JIRA_NUMBER_KEY] as String? }
  }

  fun getJwtFields(clientSettings: ClientSettings?): String? {
    return clientSettings?.let { it.settings[JWT_FIELDS_NAME_KEY] as String? }
  }

  fun mapFrom(claims: Map<String, Any>): Map<String, Any> {
    val additionalTokenSettings = HashMap<String, Any>()
    claims[CLAIMS_JIRA_NUMBER]?.let { additionalTokenSettings[JIRA_NUMBER_KEY] = it }
    return additionalTokenSettings
  }
}
