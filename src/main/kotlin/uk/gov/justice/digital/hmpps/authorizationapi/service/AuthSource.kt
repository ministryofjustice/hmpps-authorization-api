package uk.gov.justice.digital.hmpps.authorizationapi.service

import com.fasterxml.jackson.annotation.JsonValue

enum class AuthSource(val description: String) {

  Auth("External"),
  AzureAd("Microsoft Azure"),
  Delius("Delius"),
  Nomis("DPS"),
  None("None"),
  ;

  @JsonValue
  val source: String = name.lowercase()

  companion object {
    @JvmStatic
    fun fromNullableString(source: String?): AuthSource {
      if (source == null) {
        return None
      }

      return try {
        valueOf(source.lowercase().replaceFirstChar { it.titlecase() })
      } catch (e: IllegalArgumentException) {
        None
      }
    }
  }
}
