package uk.gov.justice.digital.hmpps.authorizationapi.data.model

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import java.sql.Timestamp
import java.time.Instant

internal class InstantConverterTest {
  @Test
  fun `converts a Timestamp to an Instant`() {
    val instant = Instant.now()
    val timestamp = Timestamp.from(instant)
    val actualInstant = InstantConverter.convertToEntityAttribute(timestamp)
    assertEquals(instant, actualInstant)
  }

  @Test
  fun `converts an Instant to a Timestamp`() {
    val instant = Instant.now()
    val timestamp = Timestamp.from(instant)
    val actualTimestamp = InstantConverter.convertToDatabaseColumn(instant)
    assertEquals(timestamp, actualTimestamp)
  }

  @Test
  fun `converts a null Timestamp to a null Instant`() {
    val actualInstant = InstantConverter.convertToEntityAttribute(null)
    assertNull(actualInstant)
  }

  @Test
  fun `converts a null Instant to a null Timestamp`() {
    val actualTimestamp = InstantConverter.convertToDatabaseColumn(null)
    assertNull(actualTimestamp)
  }
}
