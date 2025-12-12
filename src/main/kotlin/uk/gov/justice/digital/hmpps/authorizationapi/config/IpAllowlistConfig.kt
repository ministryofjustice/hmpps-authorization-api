package uk.gov.justice.digital.hmpps.authorizationapi.config

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Configuration

@Configuration
class IpAllowlistConfig(@Value("\${ip.allowlist.raw-mappings}") yamlIps: String) {

  companion object {
    private val log = LoggerFactory.getLogger(this::class.java)
  }

  val ipAllowlistMap: Map<String, Set<String>> = parseIpAllowlist(yamlIps)

  private final fun parseIpAllowlist(yamlIps: String): Map<String, Set<String>> {
    log.info("Generating allowlist from yamlIps")
    val resultMap = mutableMapOf<String, MutableSet<String>>()

    val truncateIpList = yamlIps.removePrefix("map[").removeSuffix("]")

    val groupEntries = truncateIpList.split("] ", "]").map { it.trim() + "]" }

    groupEntries.forEach { entry ->
      if (entry != "]") {
        val groupName = entry.substringBefore(":map")
        val innerMapString = entry.substringAfter(":map[").removeSuffix("]")

        val innerMap = mutableSetOf<String>()
        innerMapString.split(" ").mapTo(innerMap) { it.substringAfter(":") }

        resultMap[groupName] = innerMap
      }
    }
    log.info("Generated allowlist from yamlIps - {} items in map - group names - {}", resultMap.size, resultMap.keys)
    return resultMap
  }
}
