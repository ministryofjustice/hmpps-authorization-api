package uk.gov.justice.digital.hmpps.authorizationserver.data.model

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant
import java.time.LocalDateTime

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
  var accessTokenIssuedAt: Instant,

  @Column(name = "authorization_code_issued_at")
  var authorizationCodeIssuedAt: Instant,
)
