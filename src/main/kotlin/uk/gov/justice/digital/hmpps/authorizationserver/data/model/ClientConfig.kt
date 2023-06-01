package uk.gov.justice.digital.hmpps.authorizationserver.data.model

import jakarta.persistence.AttributeConverter
import jakarta.persistence.Column
import jakarta.persistence.Convert
import jakarta.persistence.Converter
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.LocalDate

@Entity
@Table(name = "OAUTH2_CLIENT_CONFIG")
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
    private val clientIdSuffixRegex = "-[0-9]*$".toRegex()
    fun baseClientId(clientId: String): String = clientId.replace(regex = clientIdSuffixRegex, replacement = "")
  }
}

@Converter
class StringListConverter : AttributeConverter<List<String>, String?> {
  override fun convertToDatabaseColumn(stringList: List<String>): String =
    stringList.filter { it.isNotEmpty() }.joinToString(",") { it.trim() }

  override fun convertToEntityAttribute(string: String?): List<String> =
    string?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()
}
