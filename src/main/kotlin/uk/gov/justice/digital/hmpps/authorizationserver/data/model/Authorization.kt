package uk.gov.justice.digital.hmpps.authorizationserver.data.model

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant

@Entity
@Table(name = "oauth2_authorization")
data class Authorization(
  @Id private val registeredClientId: String,

  @Column(name = "access_token_issued_at")
  var accessTokenIssuedAt: Instant,
)
