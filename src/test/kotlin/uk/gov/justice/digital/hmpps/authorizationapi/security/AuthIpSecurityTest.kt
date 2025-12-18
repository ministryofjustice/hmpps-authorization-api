package uk.gov.justice.digital.hmpps.authorizationapi.security

import org.assertj.core.api.Assertions.assertThatCode
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import uk.gov.justice.digital.hmpps.authorizationapi.service.IPAddressNotAllowedException

class AuthIpSecurityTest {

  @Nested
  inner class AuthLocalHostOnly {
    @Test
    fun shouldAcceptDefaultIPv4LocalHostClient() {
      val authIpSecurity = AuthIpSecurity(true)

      assertThatCode {
        authIpSecurity.validateCallReceivedFromPermittedIPAddress("127.0.0.1", "test-client")
      }.doesNotThrowAnyException()
    }

    @Test
    fun shouldAcceptFirstIPv4RangeLocalHostClient() {
      val authIpSecurity = AuthIpSecurity(true)

      assertThatCode {
        authIpSecurity.validateCallReceivedFromPermittedIPAddress("127.0.0.0", "test-client")
      }.doesNotThrowAnyException()
    }

    @Test
    fun shouldAcceptLastIPv4RangeLocalHostClient() {
      val authIpSecurity = AuthIpSecurity(true)

      assertThatCode {
        authIpSecurity.validateCallReceivedFromPermittedIPAddress("127.255.255.255", "test-client")
      }.doesNotThrowAnyException()
    }

    @Test
    fun shouldAcceptIPv6LocalHostClient() {
      val authIpSecurity = AuthIpSecurity(true)

      assertThatCode {
        authIpSecurity.validateCallReceivedFromPermittedIPAddress("::1", "test-client")
      }.doesNotThrowAnyException()
    }

    @Test
    fun shouldAcceptLocalHostClient() {
      val authIpSecurity = AuthIpSecurity(true)

      assertThatCode {
        authIpSecurity.validateCallReceivedFromPermittedIPAddress("localhost", "test-client")
      }.doesNotThrowAnyException()
    }

    @Test
    fun shouldAcceptEmptyIPAddressAsLocalHost() {
      val authIpSecurity = AuthIpSecurity(true)

      assertThatCode {
        authIpSecurity.validateCallReceivedFromPermittedIPAddress("", "test-client")
      }.doesNotThrowAnyException()
    }

    @Test
    fun shouldAcceptNullIPAddressAsLocalHost() {
      val authIpSecurity = AuthIpSecurity(true)

      assertThatCode {
        authIpSecurity.validateCallReceivedFromPermittedIPAddress(null, "test-client")
      }.doesNotThrowAnyException()
    }

    @Test
    fun shouldNotAcceptIPAddressOutsideLocalHostRange() {
      val authIpSecurity = AuthIpSecurity(true)

      assertThrows<IPAddressNotAllowedException> { authIpSecurity.validateCallReceivedFromPermittedIPAddress("172.20.0.0", "test-client") }
    }
  }

  @Nested
  inner class AuthCloudPlatformOnly {

    @Test
    fun shouldAcceptBottomOfCloudPlatformIPRange() {
      val authIpSecurity = AuthIpSecurity("172.20.0.0/16")

      assertThatCode {
        authIpSecurity.validateCallReceivedFromPermittedIPAddress("172.20.0.0", "test-client")
      }.doesNotThrowAnyException()
    }

    @Test
    fun shouldAcceptTopOfCloudPlatformIPRange() {
      val authIpSecurity = AuthIpSecurity("172.20.0.0/16")

      assertThatCode {
        authIpSecurity.validateCallReceivedFromPermittedIPAddress("172.20.255.255", "test-client")
      }.doesNotThrowAnyException()
    }

    @Test
    fun shouldNotAcceptIPOutsideCloudPlatformRange() {
      val authIpSecurity = AuthIpSecurity("172.20.0.0/16")

      assertThrows<IPAddressNotAllowedException> { authIpSecurity.validateCallReceivedFromPermittedIPAddress("171.20.255.255", "test-client") }
      assertThrows<IPAddressNotAllowedException> { authIpSecurity.validateCallReceivedFromPermittedIPAddress("172.19.255.255", "test-client") }
    }

    @Test
    fun shouldNotAcceptLocalHost() {
      val authIpSecurity = AuthIpSecurity("172.20.0.0/16")

      assertThrows<IPAddressNotAllowedException> { authIpSecurity.validateCallReceivedFromPermittedIPAddress("127.0.0.1", "test-client") }
    }
  }
}
