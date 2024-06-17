package uk.gov.justice.digital.hmpps.authorizationapi.data.model

import jakarta.persistence.AttributeConverter
import jakarta.persistence.Column
import jakarta.persistence.Converter
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import uk.gov.justice.digital.hmpps.authorizationapi.service.AuthSource
import java.sql.Timestamp
import java.time.Instant

@Entity
@Table(name = "oauth2_user_authorization_code")
data class UserAuthorizationCode(
  @Id
  val id: String,

  @Column(name = "user_name")
  val username: String,

  val userId: String,
  val userUuid: String?,
  val name: String,

  @Column(name = "source")
  var authSource: AuthSource,

  @Column(name = "authorization_code_issued_at")
  var authorizationCodeIssuedAt: Instant,
)

@Converter(autoApply = true)
class AuthSourceConverter : AttributeConverter<AuthSource, String> {
  override fun convertToDatabaseColumn(source: AuthSource?) = source?.let { source.source }

  override fun convertToEntityAttribute(persistedValue: String?): AuthSource {
    return AuthSource.fromNullableString(persistedValue)
  }
}

@Converter(autoApply = true)
class InstantConverter : AttributeConverter<Instant, Timestamp> {
  override fun convertToDatabaseColumn(source: Instant): Timestamp = Timestamp.from(source)

  override fun convertToEntityAttribute(persistedValue: Timestamp): Instant = persistedValue.toInstant()
}
