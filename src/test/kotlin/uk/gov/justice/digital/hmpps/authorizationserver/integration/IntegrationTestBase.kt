package uk.gov.justice.digital.hmpps.authorizationserver.integration

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT
import org.springframework.http.HttpHeaders
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.web.reactive.server.WebTestClient

@SpringBootTest(webEnvironment = RANDOM_PORT, properties = ["spring.main.allow-bean-definition-overriding=true"])
@ActiveProfiles("test")
abstract class IntegrationTestBase {

  @Autowired
  lateinit var jwtAuthHelper: JwtAuthHelper

  @Suppress("SpringJavaInjectionPointsAutowiringInspection")
  @Autowired
  lateinit var webTestClient: WebTestClient

  internal fun setAuthorisation(
    user: String = "AUTH_ADM",
    roles: List<String> = listOf(),
    scopes: List<String> = listOf(),
  ): (HttpHeaders) -> Unit = jwtAuthHelper.setAuthorisation(user, roles, scopes)
}
