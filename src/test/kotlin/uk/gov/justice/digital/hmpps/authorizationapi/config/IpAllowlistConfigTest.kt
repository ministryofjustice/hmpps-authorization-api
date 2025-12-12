package uk.gov.justice.digital.hmpps.authorizationapi.config

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class IpAllowlistConfigTest {

  @Test
  fun yamlParserSimpleIPGroup() {
    val yamlString = "map[group_name_a:map[ip-aa:1.1.1.1/32]]"
    val ipAllowlistConfig = IpAllowlistConfig(yamlString)

    assertThat(
      ipAllowlistConfig.ipAllowlistMap,
    ).isEqualTo(mapOf("group_name_a" to setOf("1.1.1.1/32")))
  }

  @Test
  fun yamlParserComplexIPAllowlistGroups() {
    val yamlString =
      "map[group_name_a:map[ip-aa:1.1.1.1/32 ip-ab:2.2.2.2/32 ip-ac:3.3.3.3/32 ip-ad:4.4.4.4/24 ip-ae:12.21.23.24/28] group_name_b:map[ip-ba:12.12.12.12/32 ip-bb:13.13.13.13/32] group_name_c:map[ip-ca:23.23.23.23/32 ip-cb:24.24.24.24/32] group_name_d:map[ip-dd:9.9.9.9/32 u:8.8.8.8/16 ip-ac:3.3.3.3/32]]"
    val ipAllowlistConfig = IpAllowlistConfig(yamlString)

    assertThat(ipAllowlistConfig.ipAllowlistMap).isEqualTo(
      mapOf(
        "group_name_a" to setOf("1.1.1.1/32", "2.2.2.2/32", "3.3.3.3/32", "4.4.4.4/24", "12.21.23.24/28"),
        "group_name_b" to setOf("12.12.12.12/32", "13.13.13.13/32"),
        "group_name_c" to setOf("23.23.23.23/32", "24.24.24.24/32"),
        "group_name_d" to setOf("3.3.3.3/32", "9.9.9.9/32", "8.8.8.8/16"),
      ),
    )
  }

  @Test
  fun yamlParserIPV6IPGroup() {
    val yamlString = "map[group_name_a:map[ip-v6:0:0:0:0:0:0:0:1]]"
    val ipAllowlistConfig = IpAllowlistConfig(yamlString)

    assertThat(ipAllowlistConfig.ipAllowlistMap).isEqualTo(mapOf("group_name_a" to setOf("0:0:0:0:0:0:0:1")))
  }
}
