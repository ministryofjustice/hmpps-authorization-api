package uk.gov.justice.digital.hmpps.authorizationserver.integration

import com.microsoft.applicationinsights.TelemetryClient
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.mockito.kotlin.verify
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.web.reactive.function.BodyInserters
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientType
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.Hosting
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientDeploymentRepository

class ClientDeploymentControllerIntTest : IntegrationTestBase() {

  @MockBean
  private lateinit var telemetryClient: TelemetryClient

  @Autowired
  lateinit var clientDeploymentRepository: ClientDeploymentRepository

  @Nested
  inner class AddClientDeployment {
    @Test
    fun `access forbidden when no authority`() {
      webTestClient.post().uri("/clients/deployment/add")
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
              "clientType" to "PERSONAL",
              "team" to "testing team",
              "teamContact" to "testy lead",
              "teamSlack" to "#testy",
              "hosting" to "CLOUDPLATFORM",
              "namespace" to "testy-testing-dev",
              "deployment" to "hmpps-testing-dev",
              "secretName" to "hmpps-testing",
              "clientIdKey" to "SYSTEM_CLIENT_ID",
              "secretKey" to "SYSTEM_CLIENT_SECRET",
            ),
          ),
        )
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.post().uri("/clients/deployment/add")
        .headers(setAuthorisation(roles = listOf()))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
              "clientType" to "PERSONAL",
              "team" to "testing team",
              "teamContact" to "testy lead",
              "teamSlack" to "#testy",
              "hosting" to "CLOUDPLATFORM",
              "namespace" to "testy-testing-dev",
              "deployment" to "hmpps-testing-dev",
              "secretName" to "hmpps-testing",
              "clientIdKey" to "SYSTEM_CLIENT_ID",
              "secretKey" to "SYSTEM_CLIENT_SECRET",
            ),
          ),
        )
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.post().uri("/clients/deployment/add")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
              "clientType" to "PERSONAL",
              "team" to "testing team",
              "teamContact" to "testy lead",
              "teamSlack" to "#testy",
              "hosting" to "CLOUDPLATFORM",
              "namespace" to "testy-testing-dev",
              "deployment" to "hmpps-testing-dev",
              "secretName" to "hmpps-testing",
              "clientIdKey" to "SYSTEM_CLIENT_ID",
              "secretKey" to "SYSTEM_CLIENT_SECRET",
            ),
          ),
        )
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `bad request when deployment already exists`() {
      webTestClient.post().uri("/clients/deployment/add")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
              "clientType" to "PERSONAL",
              "team" to "testing team",
              "teamContact" to "testy lead",
              "teamSlack" to "#testy",
              "hosting" to "CLOUDPLATFORM",
              "namespace" to "testy-testing-dev",
              "deployment" to "hmpps-testing-dev",
              "secretName" to "hmpps-testing",
              "clientIdKey" to "SYSTEM_CLIENT_ID",
              "secretKey" to "SYSTEM_CLIENT_SECRET",
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      webTestClient.post().uri("/clients/deployment/add")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
            ),
          ),
        )
        .exchange()
        .expectStatus().isBadRequest
        .expectBody()
        .json(
          """
              {
              "userMessage":"ClientDeployment for client id testy already exists",
              "developerMessage":"ClientDeployment for client id testy already exists"
              }
          """
            .trimIndent(),
        )
    }

    @Test
    fun `add client deployment success`() {
      webTestClient.post().uri("/clients/deployment/add")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "mctesty",
              "clientType" to "PERSONAL",
              "team" to "testing team",
              "teamContact" to "testy lead",
              "teamSlack" to "#testy",
              "hosting" to "CLOUDPLATFORM",
              "namespace" to "testy-testing-dev",
              "deployment" to "hmpps-testing-dev",
              "secretName" to "hmpps-testing",
              "clientIdKey" to "SYSTEM_CLIENT_ID",
              "secretKey" to "SYSTEM_CLIENT_SECRET",
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      val clientDeployment = clientDeploymentRepository.findById("mctesty").get()
      assertThat(clientDeployment.baseClientId).isEqualTo("mctesty")
      assertThat(clientDeployment.clientType).isEqualTo(ClientType.PERSONAL)
      assertThat(clientDeployment.team).isEqualTo("testing team")
      assertThat(clientDeployment.teamContact).isEqualTo("testy lead")
      assertThat(clientDeployment.teamSlack).isEqualTo("#testy")
      assertThat(clientDeployment.hosting).isEqualTo(Hosting.CLOUDPLATFORM)
      assertThat(clientDeployment.namespace).isEqualTo("testy-testing-dev")
      assertThat(clientDeployment.deployment).isEqualTo("hmpps-testing-dev")
      assertThat(clientDeployment.secretName).isEqualTo("hmpps-testing")
      assertThat(clientDeployment.clientIdKey).isEqualTo("SYSTEM_CLIENT_ID")
      assertThat(clientDeployment.secretKey).isEqualTo("SYSTEM_CLIENT_SECRET")

      verify(telemetryClient).trackEvent(
        "AuthorizationServerClientDeploymentDetailsUpdated",
        mapOf("username" to "AUTH_ADM", "baseClientId" to "mctesty"),
        null,
      )
    }
  }
}
