package uk.gov.justice.digital.hmpps.authorizationserver.security

import com.fasterxml.jackson.annotation.JsonValue

enum class AuthSource(val description: String) {
  auth("External"), azuread("Microsoft Azure"), delius("Delius"), nomis("DPS"), none("None"); // ktlint-disable enum-entry-name-case

  @JsonValue
  val source: String = name

  companion object {
    @JvmStatic
    fun fromNullableString(source: String?): AuthSource {
      return source?.let { valueOf(source.lowercase()) } ?: none
    }

    fun getSourceLegacyName(source: String?): String? {
      return when (fromNullableString(source)) {
        delius -> "nDelius"
        nomis -> "NOMIS"
        else -> null
      }
    }
  }
}
