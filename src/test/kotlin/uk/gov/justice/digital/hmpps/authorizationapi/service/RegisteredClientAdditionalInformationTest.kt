package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.time.Duration
import java.time.format.DateTimeParseException

class RegisteredClientAdditionalInformationTest {

  private lateinit var registeredClientAdditionalInfo: RegisteredClientAdditionalInformation

  @ParameterizedTest
  @MethodSource("uk.gov.justice.digital.hmpps.authorizationapi.service.RegisteredClientAdditionalInformationTest#testCases")
  fun `buildTokenSettings configures authorizationCodeTimeToLive with the expected value`(testCase: TestCase) {
    registeredClientAdditionalInfo = RegisteredClientAdditionalInformation(testCase.authorizationCodeTTL)

    val tokenSettings = registeredClientAdditionalInfo.buildTokenSettings(1)

    assertThat(tokenSettings).isNotNull
    assertThat(tokenSettings.authorizationCodeTimeToLive).isEqualTo(testCase.expectedDuration)
  }

  @Test
  fun `buildTokenSettings throws the expected exception when authorizationCodeTimeToLive is not a valid duration string`() {
    registeredClientAdditionalInfo = RegisteredClientAdditionalInformation("this 1s n0t a V4l1d duration strinG!!")

    assertThrows<DateTimeParseException> { registeredClientAdditionalInfo.buildTokenSettings(1) }
  }

  data class TestCase(
    val description: String,
    val authorizationCodeTTL: String?,
    val expectedDuration: Duration,
  )

  companion object {
    private val DEFAULT_DURATION = Duration.ofMinutes(5)

    @JvmStatic
    fun testCases() = listOf(
      TestCase(
        description = "authorizationCodeTimeToLive defaults to 5 minutes if authorizationCodeTTL is null",
        authorizationCodeTTL = null,
        expectedDuration = DEFAULT_DURATION,
      ),
      TestCase(
        description = "authorizationCodeTimeToLive defaults to 5 minutes if authorizationCodeTTL is empty",
        authorizationCodeTTL = "",
        expectedDuration = DEFAULT_DURATION,
      ),
      TestCase(
        description = "authorizationCodeTimeToLive defaults to 5 minutes if authorizationCodeTTL is empty with multiple spaces",
        authorizationCodeTTL = "    ",
        expectedDuration = DEFAULT_DURATION,
      ),
      TestCase(
        description = "authorizationCodeTimeToLive is set to the provided duration when authorizationCodeTTL is a valid duration with whitespace",
        authorizationCodeTTL = " PT20M ",
        expectedDuration = Duration.ofMinutes(20),
      ),
      TestCase(
        description = "authorizationCodeTimeToLive is set to the provided duration when authorizationCodeTTL is a valid duration",
        authorizationCodeTTL = "PT10M",
        expectedDuration = Duration.ofMinutes(10),
      ),
    )
  }
}
