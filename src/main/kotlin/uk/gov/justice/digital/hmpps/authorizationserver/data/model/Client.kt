package uk.gov.justice.digital.hmpps.authorizationserver.data.model

import jakarta.persistence.AttributeConverter
import jakarta.persistence.Column
import jakarta.persistence.Convert
import jakarta.persistence.Converter
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import uk.gov.justice.digital.hmpps.authorizationserver.utils.OAuthJson
import java.time.Instant

@Entity
@Table(name = "oauth2_registered_client")
data class Client(

  @Id
  val id: String?, // TODO configure generation
  val clientId: String,

  val clientIdIssuedAt: Instant,
  val clientSecret: String,
  val clientSecretExpiresAt: Instant? = null,
  val clientName: String,

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
  val tokenSettings: TokenSettings,

  @Column(length = 255)
  @Convert(converter = MapConverter::class)
  var additionalInformation: Map<String, Any>?,
)

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
class MapConverter(private val oAuthJson: OAuthJson) : AttributeConverter<Map<String, Any>, String> {

  override fun convertToDatabaseColumn(attribute: Map<String, Any>?): String? {
    return oAuthJson.toJsonString(attribute)
  }

  override fun convertToEntityAttribute(dbData: String?): Map<String, Any>? {
    return oAuthJson.readValueFrom(dbData, LinkedHashMap::class.java) as Map<String, Any>?
  }
}

@Converter
class StringListConverter : AttributeConverter<List<String>, String?> {
  override fun convertToDatabaseColumn(stringList: List<String>): String =
    stringList.filter { it.isNotEmpty() }.joinToString(",") { it.trim() }

  override fun convertToEntityAttribute(string: String?): List<String> =
    string?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()
}
