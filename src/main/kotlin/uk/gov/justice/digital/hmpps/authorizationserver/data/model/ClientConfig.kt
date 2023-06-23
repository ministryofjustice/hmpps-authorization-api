package uk.gov.justice.digital.hmpps.authorizationserver.data.model

import jakarta.persistence.Column
import jakarta.persistence.Convert
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.LocalDate

@Entity
@Table(name = "oauth2_client_config")
data class ClientConfig(
  @Id
  @Column(name = "base_client_id", nullable = false)
  var baseClientId: String,

  @Column(name = "allowed_ips")
  @Convert(converter = StringListConverter::class)
  var ips: List<String> = emptyList(),

  @Column(name = "client_end_date")
  var clientEndDate: LocalDate? = null,
) {

  companion object {
    // TODO decision required on whether we will use this

    private val clientIdSuffixRegex = "-[0-9]*$".toRegex()
    fun baseClientId(clientId: String): String = clientId.replace(regex = clientIdSuffixRegex, replacement = "")
  }
}
