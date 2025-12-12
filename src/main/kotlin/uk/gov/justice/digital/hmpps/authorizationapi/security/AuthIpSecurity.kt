package uk.gov.justice.digital.hmpps.authorizationapi.security

import com.microsoft.applicationinsights.TelemetryClient
import org.slf4j.LoggerFactory
import org.springframework.security.web.util.matcher.IpAddressMatcher
import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationapi.config.IpAllowlistConfig
import uk.gov.justice.digital.hmpps.authorizationapi.service.IPAddressNotAllowedException

@Component
class AuthIpSecurity(
  private val parseIpAllowlistConfig: IpAllowlistConfig,
  private val telemetryClient: TelemetryClient,
) {
  companion object {
    private val log = LoggerFactory.getLogger(this::class.java)
  }

  fun validateClientIpAllowed(remoteIp: String?, clientAllowlist: List<String>, clientId: String) {
    val ipAllowlist = combineIpsAndNamedIpAllowlists(clientAllowlist, clientId)

    val matchIp = ipAllowlist.any { ip: String? -> IpAddressMatcher(ip).matches(remoteIp) }
    if (!matchIp) {
      log.warn("Client {} IP {}, is not in client allowlist {}", clientId, remoteIp, ipAllowlist)
      throw IPAddressNotAllowedException()
    }
  }

  fun combineIpsAndNamedIpAllowlists(clientAllowlist: List<String>, clientId: String): MutableSet<String> {
    val ipAllowlist = mutableSetOf<String>()

    val ipAllowlistMap = parseIpAllowlistConfig.ipAllowlistMap

    clientAllowlist.forEach { ipEntry: String? ->
      if (!ipEntry!!.first().isLetter()) {
        ipAllowlist.add(ipEntry)
      } else {
        if (ipAllowlistMap.containsKey(ipEntry)) {
          ipAllowlistMap[ipEntry]?.forEach {
            val i = it
            ipAllowlist.add(it.trim())
          }
        } else {
          telemetryClient.trackEvent(
            "NamedIpAllowlistGroupNotFound",
            mapOf(
              "GroupName" to ipEntry,
              "clientId" to clientId,
            ),
            null,
          )
        }
      }
    }
    return ipAllowlist
  }
}
