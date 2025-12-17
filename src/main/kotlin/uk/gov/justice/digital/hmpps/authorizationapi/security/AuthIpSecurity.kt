package uk.gov.justice.digital.hmpps.authorizationapi.security

import org.slf4j.LoggerFactory
import org.springframework.security.web.util.matcher.IpAddressMatcher
import uk.gov.justice.digital.hmpps.authorizationapi.service.IPAddressNotAllowedException
import java.net.InetAddress

class AuthIpSecurity(
  private val localHostOnly: Boolean,
) {

  constructor(authIPAddressRange: String) : this(false) {
    this.ipAddressMatcher = IpAddressMatcher(authIPAddressRange)
  }

  private lateinit var ipAddressMatcher: IpAddressMatcher

  companion object {
    private val log = LoggerFactory.getLogger(this::class.java)
  }

  fun validateCallReceivedFromPermittedIPAddress(remoteIp: String?, clientId: String) {
    if (localHostOnly) {
      if (!isLocalHost(remoteIp)) {
        log.warn("Call detected from non local host IP address: Client {} IP {}", clientId, remoteIp)
        throw IPAddressNotAllowedException()
      }
    } else {
      val matchIpx = ipAddressMatcher.matches(remoteIp)
      if (!matchIpx) {
        log.warn("Call detected from blocked IP address: Client {} IP {}", clientId, remoteIp)
        throw IPAddressNotAllowedException()
      }
    }
  }

  private fun isLocalHost(remoteIp: String?): Boolean {
    val inetAddress = InetAddress.getByName(remoteIp)
    return inetAddress.isLoopbackAddress
  }
}
