package uk.gov.justice.digital.hmpps.authorizationserver.data.model

import jakarta.persistence.AttributeConverter
import jakarta.persistence.Column
import jakarta.persistence.Convert
import jakarta.persistence.Converter
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.JoinColumn
import jakarta.persistence.OneToMany
import jakarta.persistence.Table
import org.hibernate.annotations.Where
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import uk.gov.justice.digital.hmpps.authorizationserver.service.RegisteredClientAdditionalInformation.Companion.DATABASE_USER_NAME_KEY
import uk.gov.justice.digital.hmpps.authorizationserver.service.RegisteredClientAdditionalInformation.Companion.JIRA_NUMBER_KEY
import uk.gov.justice.digital.hmpps.authorizationserver.utils.OAuthJson
import java.time.Instant
import kotlin.jvm.optionals.getOrElse

@Entity
@Table(name = "oauth2_registered_client")
data class Client(

  @Id
  val id: String?,
  var clientId: String,

  val clientIdIssuedAt: Instant,
  var clientSecret: String? = null,
  val clientSecretExpiresAt: Instant? = null,
  var clientName: String,

  @Column(length = 1000)
  val clientAuthenticationMethods: String,

  @Column(length = 1000)
  val authorizationGrantTypes: String,

  @Column(length = 1000)
  val redirectUris: String? = null,

  @Column(length = 1000)
  val postLogoutRedirectUris: String? = null,

  @Column(length = 1000)
  @Convert(converter = StringListConverter::class)
  var scopes: List<String> = emptyList(),

  @Column(length = 2000)
  @Convert(converter = ClientSettingsConverter::class)
  val clientSettings: ClientSettings,

  @Column(length = 2000)
  @Convert(converter = TokenSettingsConverter::class)
  var tokenSettings: TokenSettings,

  @OneToMany
  @JoinColumn(name = "registeredClientId")
  @Where(clause = "access_token_issued_at =(select max(oa.access_token_issued_at) from oauth2_authorization oa)")
  val latestClientCredentialsAuthorization: MutableSet<Authorization> ? = mutableSetOf(),
) {

  fun getDatabaseUserName(): String? {
    return tokenSettings.settings[DATABASE_USER_NAME_KEY] as String?
  }

  fun getLastAccessedDate(): Instant? {
    return this.latestClientCredentialsAuthorization?.stream()?.findFirst()?.map { it.accessTokenIssuedAt }?.getOrElse { clientIdIssuedAt }
  }

  fun getJiraNumber(): String? {
    return tokenSettings.settings[JIRA_NUMBER_KEY] as String?
  }
}

@Converter
class TokenSettingsConverter(private val oAuthJson: OAuthJson) : AttributeConverter<TokenSettings, String> {

  override fun convertToDatabaseColumn(attribute: TokenSettings): String {
    return oAuthJson.toJsonString(attribute.settings)!!
  }

  override fun convertToEntityAttribute(dbData: String): TokenSettings {
    val settings = oAuthJson.readValueFrom(dbData, Map::class.java) as Map<String, Any>
    return TokenSettings.withSettings(settings).build()
  }
}

@Converter
class ClientSettingsConverter(private val oAuthJson: OAuthJson) : AttributeConverter<ClientSettings, String> {

  override fun convertToDatabaseColumn(attribute: ClientSettings): String {
    return oAuthJson.toJsonString(attribute.settings)!!
  }

  override fun convertToEntityAttribute(dbData: String): ClientSettings {
    val settings = oAuthJson.readValueFrom(dbData, Map::class.java) as Map<String, Any>
    return ClientSettings.withSettings(settings).build()
  }
}

@Converter
class StringListConverter : AttributeConverter<List<String>, String?> {
  override fun convertToDatabaseColumn(stringList: List<String>): String =
    stringList.filter { it.isNotEmpty() }.joinToString(",") { it.trim() }

  override fun convertToEntityAttribute(string: String?): List<String> =
    string?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()
}
