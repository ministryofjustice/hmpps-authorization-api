package uk.gov.justice.digital.hmpps.authorizationapi.data.model

import jakarta.persistence.Column
import jakarta.persistence.Convert
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant

@Entity
@Table(name = "oauth2_authorization")
data class Authorization(
  @Id
  val id: String,

  private val registeredClientId: String,

  @Column(name = "principal_name")
  private val principalName: String,

  private val authorizationGrantType: String,

  @Column(name = "access_token_issued_at")
  @Convert(converter = InstantConverter::class)
  var accessTokenIssuedAt: Instant?,

  @Column(name = "authorization_code_issued_at")
  @Convert(converter = InstantConverter::class)
  var authorizationCodeIssuedAt: Instant?,

  @Column(name = "authorization_code_expires_at")
  @Convert(converter = InstantConverter::class)
  var authorizationCodeExpiresAt: Instant?,
)
