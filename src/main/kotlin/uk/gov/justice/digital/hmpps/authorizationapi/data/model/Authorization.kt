package uk.gov.justice.digital.hmpps.authorizationapi.data.model

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.LocalDateTime

@Entity
@Table(name = "oauth2_authorization")
data class Authorization(
  @Id
  val id: String,

  val registeredClientId: String,

  val principalName: String,

  val authorizationGrantType: String,

  @Column(length = 1000)
  val authorizedScopes: String?,

  @Column(length = 4000)
  val attributes: String?,

  @Column(length = 500)
  val state: String? = null,

  @Column(length = 4000)
  val authorizationCodeValue: String?,

  var authorizationCodeIssuedAt: LocalDateTime?,

  var authorizationCodeExpiresAt: LocalDateTime?,

  val authorizationCodeMetadata: String?,
)
