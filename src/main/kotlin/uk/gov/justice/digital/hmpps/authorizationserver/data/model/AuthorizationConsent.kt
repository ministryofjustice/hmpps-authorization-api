package uk.gov.justice.digital.hmpps.authorizationserver.data.model

import jakarta.persistence.Column
import jakarta.persistence.Convert
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.IdClass
import jakarta.persistence.Table
import java.io.Serializable

@Entity
@IdClass(AuthorizationConsent.AuthorizationConsentId::class)
@Table(name = "oauth2_authorization_consent")
data class AuthorizationConsent(
  @Id private val registeredClientId: String,
  @Id private val principalName: String,

  @Column(name = "authorities")
  @Convert(converter = StringListConverter::class)
  val authorities: List<String> = emptyList(),
) {

  class AuthorizationConsentId(
    private var registeredClientId: String?,
    private var principalName: String?,
  ) : Serializable {
    constructor() : this(null, null)
  }
}
