package uk.gov.justice.digital.hmpps.authorizationapi.data.model

import jakarta.persistence.AttributeConverter
import jakarta.persistence.Column
import jakarta.persistence.Converter
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import uk.gov.justice.digital.hmpps.authorizationapi.service.AuthSource
import java.time.LocalDateTime

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
  val jwtId: String,

  @Column(name = "source")
  var authSource: AuthSource,

  @Column(name = "authorization_code_issued_at")
  var authorizationCodeIssuedAt: LocalDateTime,
)

@Converter(autoApply = true)
class AuthSourceConverter : AttributeConverter<AuthSource, String> {
  override fun convertToDatabaseColumn(source: AuthSource?) = source?.let { source.source }

  override fun convertToEntityAttribute(persistedValue: String?): AuthSource = AuthSource.fromNullableString(persistedValue)
}
