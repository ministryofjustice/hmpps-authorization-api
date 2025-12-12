package uk.gov.justice.digital.hmpps.authorizationapi.security

import com.microsoft.applicationinsights.TelemetryClient
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatCode
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import uk.gov.justice.digital.hmpps.authorizationapi.config.IpAllowlistConfig
import uk.gov.justice.digital.hmpps.authorizationapi.service.IPAddressNotAllowedException

class AuthIpSecurityTest {

  private val telemetryClient: TelemetryClient = mock()

  @Nested
  inner class ClientIpCheck {
    @Test
    fun testStandardV4IP() {
      val ipAllowlistConfig: IpAllowlistConfig = mock()
      whenever(ipAllowlistConfig.ipAllowlistMap).thenReturn(mapOf("group_name_a" to setOf("1.1.1.1/32")))
      val testClass = AuthIpSecurity(ipAllowlistConfig, telemetryClient)
      assertThatCode {
        testClass.validateClientIpAllowed("127.0.0.1", listOf("127.0.0.1"), "client-a")
      }.doesNotThrowAnyException()
    }

    @Test
    fun testRemoteAddressNotInAllowlist() {
      val ipAllowlistConfig: IpAllowlistConfig = mock()
      whenever(ipAllowlistConfig.ipAllowlistMap).thenReturn(mapOf("group_name_a" to setOf("1.1.1.1/32")))
      val testClass = AuthIpSecurity(ipAllowlistConfig, telemetryClient)
      assertThatThrownBy {
        testClass.validateClientIpAllowed(
          "82.34.12.11",
          listOf("82.34.12.10/32", "82.34.12.12/32"),
          "client-a",
        )
      }
        .isInstanceOf(
          IPAddressNotAllowedException::class.java,
        ).hasMessage("Unable to issue token as request is not from ip within allowed list")
    }

    @Test
    fun testIpV6Address() {
      val ipAllowlistConfig: IpAllowlistConfig = mock()
      whenever(ipAllowlistConfig.ipAllowlistMap).thenReturn(mapOf("group_name_a" to setOf("1.1.1.1/32")))
      val testClass = AuthIpSecurity(ipAllowlistConfig, telemetryClient)
      assertThatCode {
        testClass.validateClientIpAllowed("0:0:0:0:0:0:0:1", listOf("0:0:0:0:0:0:0:1", "127.0.0.1/32"), "client-a")
      }.doesNotThrowAnyException()
    }

    @Test
    fun testRemoteIpV6AddressNotInAllowlist() {
      val ipAllowlistConfig: IpAllowlistConfig = mock()
      whenever(ipAllowlistConfig.ipAllowlistMap).thenReturn(mapOf("group_name_a" to setOf("1.1.1.1/32")))
      val testClass = AuthIpSecurity(ipAllowlistConfig, telemetryClient)
      assertThatThrownBy {
        testClass.validateClientIpAllowed(
          "0:0:0:0:0:0:0:1",
          listOf("0:0:0:0:0:0:0:2", "82.34.12.10/32", "82.34.12.12/32"),
          "client-a",
        )
      }
        .isInstanceOf(
          IPAddressNotAllowedException::class.java,
        ).hasMessage("Unable to issue token as request is not from ip within allowed list")
    }
  }

  @Nested
  inner class IpNameCheck {

    @Test
    fun testNamedIpAddressInAllowlist() {
      val ipAllowlistConfig: IpAllowlistConfig = mock()
      whenever(ipAllowlistConfig.ipAllowlistMap).thenReturn(
        mapOf(
          "group_name_a" to setOf("1.1.1.1/32", "2.2.2.2/32"),
          "group_name_b" to setOf("12.12.12.12/28", "13.13.13.13"),
        ),
      )
      val testClass = AuthIpSecurity(
        ipAllowlistConfig,
        telemetryClient,
      )
      assertThatCode {
        testClass.validateClientIpAllowed(
          "1.1.1.1",
          listOf("group_name_a"),
          "client-a",
        )
      }.doesNotThrowAnyException()
    }

    @Test
    fun testIncorrectlyNamedIpGroupIpInAllowlist() {
      val ipAllowlistConfig: IpAllowlistConfig = mock()
      whenever(ipAllowlistConfig.ipAllowlistMap).thenReturn(
        mapOf(
          "group_name_a" to setOf("21.21.21.21/32", "2.2.2.2/32"),
          "group_name_b" to setOf("12.12.12.12/28", "13.13.13.13"),
        ),
      )
      val testClass = AuthIpSecurity(ipAllowlistConfig, telemetryClient)
      assertThatCode {
        testClass.validateClientIpAllowed(
          "1.1.1.2",
          listOf("1.1.1.2", "groupZ"),
          "client-a",
        )
      }.doesNotThrowAnyException()
    }

    @Test
    fun testOnlyNamedIpAddressInAllowlist() {
      val ipAllowlistConfig: IpAllowlistConfig = mock()
      whenever(ipAllowlistConfig.ipAllowlistMap).thenReturn(
        mapOf(
          "group_name_a" to setOf("1.1.1.1/32", "2.2.2.2/32"),
          "group_name_b" to setOf("12.12.12.12/28", "13.13.13.13"),
          "group_name_c" to setOf("14.15.1.62/32", "23.23.23.23/32"),
          "group_name_d" to setOf("145.152.12.12/32", "33.33.33.33/32"),
          "group_name_e" to setOf("134.132.12.12/32", "43.43.13.13"),
          "group_name_f" to setOf("81.212.12.12/32", "35.53.35.53/32"),
          "group_name_g" to setOf("72.82.92.112/32", "63.13.13.13"),
        ),
      )
      val testClass = AuthIpSecurity(ipAllowlistConfig, telemetryClient)
      assertThatCode {
        testClass.validateClientIpAllowed(
          "72.82.92.112",
          listOf("group_name_g"),
          "client-a",
        )
      }.doesNotThrowAnyException()
    }

    @Test
    fun testNamedIpAddressNotInAllowlist() {
      val ipAllowlistConfig: IpAllowlistConfig = mock()
      val testClass = AuthIpSecurity(ipAllowlistConfig, telemetryClient)

      assertThatThrownBy {
        testClass.validateClientIpAllowed(
          "0:0:0:0:0:0:0:1",
          listOf("group_name_a"),
          "client-a",
        )
      }.isInstanceOf(
        IPAddressNotAllowedException::class.java,
      ).hasMessage("Unable to issue token as request is not from ip within allowed list")
    }

    @Nested
    inner class CombineIPList {

      private val ipMap = mapOf(
        "group_name_a" to setOf("1.1.1.1/32", "2.2.2.2/32", "3.3.3.3/32", "4.4.4.4/24", "12.21.23.24/28"),
        "group_name_b" to setOf("12.12.12.12/32", "13.13.13.13/32"),
        "group_name_c" to setOf("23.23.23.23/32", "24.24.24.24/32"),
        "group_name_d" to setOf("3.3.3.3/32", "9.9.9.9/32", "8.8.8.8/16"),
        "group_name_e" to setOf("0:0:0:0:0:0:0:1"),
      )

      @Test
      fun combineIpAndAllowlistGroupNoGroupPassed() {
        val ipAllowlistConfig: IpAllowlistConfig = mock()
        val testClass = AuthIpSecurity(ipAllowlistConfig, telemetryClient)
        whenever(ipAllowlistConfig.ipAllowlistMap).thenReturn(ipMap)

        val map = testClass.combineIpsAndNamedIpAllowlists(listOf("1.0.0.0/32"), "client-a")

        assertThat(map).isEqualTo(
          setOf("1.0.0.0/32"),
        )
      }

      @Test
      fun combineIpAndAllowlistGroup() {
        val ipAllowlistConfig: IpAllowlistConfig = mock()
        val testClass = AuthIpSecurity(ipAllowlistConfig, telemetryClient)
        whenever(ipAllowlistConfig.ipAllowlistMap).thenReturn(ipMap)

        val map = testClass.combineIpsAndNamedIpAllowlists(listOf("1.0.0.0/32", "group_name_a"), "client-a")

        assertThat(map).isEqualTo(
          setOf("1.0.0.0/32", "1.1.1.1/32", "2.2.2.2/32", "3.3.3.3/32", "4.4.4.4/24", "12.21.23.24/28"),
        )
      }

      @Test
      fun combineIpAndMultipleAllowlistGroup() {
        val ipAllowlistConfig: IpAllowlistConfig = mock()
        val testClass = AuthIpSecurity(ipAllowlistConfig, telemetryClient)
        whenever(ipAllowlistConfig.ipAllowlistMap).thenReturn(ipMap)

        val map = testClass.combineIpsAndNamedIpAllowlists(listOf("1.0.0.0/32", "group_name_a", "group_name_e"), "client-a")

        assertThat(map).isEqualTo(
          setOf(
            "1.0.0.0/32",
            "1.1.1.1/32",
            "2.2.2.2/32",
            "3.3.3.3/32",
            "4.4.4.4/24",
            "12.21.23.24/28",
            "0:0:0:0:0:0:0:1",
          ),
        )
      }

      @Test
      fun combineIpAllowlistGroupMissing() {
        val ipAllowlistConfig: IpAllowlistConfig = mock()
        val testClass = AuthIpSecurity(ipAllowlistConfig, telemetryClient)
        whenever(ipAllowlistConfig.ipAllowlistMap).thenReturn(ipMap)

        val map = testClass.combineIpsAndNamedIpAllowlists(listOf("1.0.0.0/32", "group_name_z"), "client-a")

        assertThat(map).isEqualTo(
          setOf("1.0.0.0/32"),
        )

        verify(telemetryClient).trackEvent(
          "NamedIpAllowlistGroupNotFound",
          mapOf("GroupName" to "group_name_z", "clientId" to "client-a"),
          null,
        )
      }

      @Test
      fun combineIpMultiplyAllowlistGroupOneMissing() {
        val ipAllowlistConfig: IpAllowlistConfig = mock()
        val testClass = AuthIpSecurity(ipAllowlistConfig, telemetryClient)
        whenever(ipAllowlistConfig.ipAllowlistMap).thenReturn(ipMap)

        val map = testClass.combineIpsAndNamedIpAllowlists(listOf("1.0.0.0/32", "group_name_e", "group_name_z"), "client-a")

        assertThat(map).isEqualTo(
          setOf("1.0.0.0/32", "0:0:0:0:0:0:0:1"),
        )

        verify(telemetryClient).trackEvent(
          "NamedIpAllowlistGroupNotFound",
          mapOf("GroupName" to "group_name_z", "clientId" to "client-a"),
          null,
        )
      }
    }
  }

  @Nested
  inner class CombineIPList {

    private val ipMap = mapOf(
      "group_name_a" to setOf("1.1.1.1/32", "2.2.2.2/32", "3.3.3.3/32", "4.4.4.4/24", "12.21.23.24/28"),
      "group_name_b" to setOf("12.12.12.12/32", "13.13.13.13/32"),
      "group_name_c" to setOf("23.23.23.23/32", "24.24.24.24/32"),
      "group_name_d" to setOf("3.3.3.3/32", "9.9.9.9/32", "8.8.8.8/16"),
      "group_name_e" to setOf("0:0:0:0:0:0:0:1"),
    )

    @Test
    fun combineIpAndAllowlistGroupNoGroupPassed() {
      val ipAllowlistConfig: IpAllowlistConfig = mock()
      val testClass = AuthIpSecurity(ipAllowlistConfig, telemetryClient)
      whenever(ipAllowlistConfig.ipAllowlistMap).thenReturn(ipMap)

      val map = testClass.combineIpsAndNamedIpAllowlists(listOf("1.0.0.0/32"), "client-a")

      assertThat(map).isEqualTo(
        setOf("1.0.0.0/32"),
      )
    }

    @Test
    fun combineIpAndAllowlistGroup() {
      val ipAllowlistConfig: IpAllowlistConfig = mock()
      val testClass = AuthIpSecurity(ipAllowlistConfig, telemetryClient)
      whenever(ipAllowlistConfig.ipAllowlistMap).thenReturn(ipMap)

      val map = testClass.combineIpsAndNamedIpAllowlists(listOf("1.0.0.0/32", "group_name_a"), "client-a")

      assertThat(map).isEqualTo(
        setOf("1.0.0.0/32", "1.1.1.1/32", "2.2.2.2/32", "3.3.3.3/32", "4.4.4.4/24", "12.21.23.24/28"),
      )
    }

    @Test
    fun combineIpAndMultipleAllowlistGroup() {
      val ipAllowlistConfig: IpAllowlistConfig = mock()
      val testClass = AuthIpSecurity(ipAllowlistConfig, telemetryClient)
      whenever(ipAllowlistConfig.ipAllowlistMap).thenReturn(ipMap)

      val map = testClass.combineIpsAndNamedIpAllowlists(listOf("1.0.0.0/32", "group_name_a", "group_name_e"), "client-a")

      assertThat(map).isEqualTo(
        setOf(
          "1.0.0.0/32",
          "1.1.1.1/32",
          "2.2.2.2/32",
          "3.3.3.3/32",
          "4.4.4.4/24",
          "12.21.23.24/28",
          "0:0:0:0:0:0:0:1",
        ),
      )
    }

    @Test
    fun combineIpAllowlistGroupMissing() {
      val ipAllowlistConfig: IpAllowlistConfig = mock()
      val testClass = AuthIpSecurity(ipAllowlistConfig, telemetryClient)
      whenever(ipAllowlistConfig.ipAllowlistMap).thenReturn(ipMap)

      val map = testClass.combineIpsAndNamedIpAllowlists(listOf("1.0.0.0/32", "group_name_z"), "client-a")

      assertThat(map).isEqualTo(
        setOf("1.0.0.0/32"),
      )

      verify(telemetryClient).trackEvent(
        "NamedIpAllowlistGroupNotFound",
        mapOf("GroupName" to "group_name_z", "clientId" to "client-a"),
        null,
      )
    }

    @Test
    fun combineIpMultiplyAllowlistGroupOneMissing() {
      val ipAllowlistConfig: IpAllowlistConfig = mock()
      val testClass = AuthIpSecurity(ipAllowlistConfig, telemetryClient)
      whenever(ipAllowlistConfig.ipAllowlistMap).thenReturn(ipMap)

      val map = testClass.combineIpsAndNamedIpAllowlists(listOf("1.0.0.0/32", "group_name_e", "group_name_z"), "client-a")

      assertThat(map).isEqualTo(
        setOf("1.0.0.0/32", "0:0:0:0:0:0:0:1"),
      )

      verify(telemetryClient).trackEvent(
        "NamedIpAllowlistGroupNotFound",
        mapOf("GroupName" to "group_name_z", "clientId" to "client-a"),
        null,
      )
    }
  }
}
