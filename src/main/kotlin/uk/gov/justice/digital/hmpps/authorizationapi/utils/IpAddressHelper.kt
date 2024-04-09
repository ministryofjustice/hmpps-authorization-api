package uk.gov.justice.digital.hmpps.authorizationapi.utils

import jakarta.servlet.http.HttpServletRequest
import org.apache.commons.lang3.StringUtils.split
import org.springframework.stereotype.Component
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.context.request.ServletRequestAttributes

/**
 * NOTE:
 *
 * Azure provides ip addresses with a port, which we need to strip out before using.
 * Colons are counted to avoid breaking IP6 addresses
 */
@Component
class IpAddressHelper {

  fun retrieveIpFromRequest(): String {
    val requestAttributes = RequestContextHolder.currentRequestAttributes()
    return retrieveIpFromRemoteAddress((requestAttributes as ServletRequestAttributes).request)
  }

  private fun retrieveIpFromRemoteAddress(request: HttpServletRequest): String {
    val remoteAddress = request.remoteAddr
    val colonCount = remoteAddress.chars().filter { ch: Int -> ch == ':'.code }.count()
    return if (colonCount == 1L) split(remoteAddress, ":")[0] else remoteAddress
  }
}
