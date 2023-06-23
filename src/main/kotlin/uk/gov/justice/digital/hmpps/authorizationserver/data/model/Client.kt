package uk.gov.justice.digital.hmpps.authorizationserver.data.model

import jakarta.persistence.AttributeConverter
import jakarta.persistence.Column
import jakarta.persistence.Converter
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant

@Entity
@Table(name = "oauth2_registered_client")
data class Client(

  @Id
  val id: String?, // TODO configure generation
  val clientId: String,

  private val clientIdIssuedAt: Instant,
  private val clientSecret: String?,
  private val clientSecretExpiresAt: Instant? = null,
  private val clientName: String,

  @Column(length = 1000)
  private val clientAuthenticationMethods: String,

  @Column(length = 1000)
  private val authorizationGrantTypes: String,

  @Column(length = 1000)
  private val redirectUris: String? = null,

  @Column(length = 1000)
  private val postLogoutRedirectUris: String? = null,

  @Column(length = 1000)
  private val scopes: String,

  @Column(length = 2000)
  private val clientSettings: String,

  @Column(length = 2000)
  private val tokenSettings: String,
)

@Converter
class StringListConverter : AttributeConverter<List<String>, String?> {
  override fun convertToDatabaseColumn(stringList: List<String>): String =
    stringList.filter { it.isNotEmpty() }.joinToString(",") { it.trim() }

  override fun convertToEntityAttribute(string: String?): List<String> =
    string?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()
}
