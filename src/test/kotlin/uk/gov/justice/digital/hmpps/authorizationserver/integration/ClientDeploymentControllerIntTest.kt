package uk.gov.justice.digital.hmpps.authorizationserver.integration

import com.microsoft.applicationinsights.TelemetryClient
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.mock.mockito.MockBean
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientDeploymentRepository

class ClientDeploymentControllerIntTest : IntegrationTestBase() {

  @MockBean
  private lateinit var telemetryClient: TelemetryClient

  @Autowired
  lateinit var clientDeploymentRepository: ClientDeploymentRepository

/*  @Nested
  inner class UpdateClientDeployment {

    @Test
    fun `update client deployment success`() {
      webTestClient.post().uri("/clients/dctesty/deployment")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientType" to "PERSONAL",
              "team" to "HAAR",
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
      webTestClient.put().uri("/clients/dctesty/deployment")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientType" to "PERSONAL",
              "team" to "HAAR team",
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

      val clientDeployment = clientDeploymentRepository.findById("dctesty").get()
      assertThat(clientDeployment.baseClientId).isEqualTo("dctesty")
      assertThat(clientDeployment.clientType).isEqualTo(ClientType.PERSONAL)
      assertThat(clientDeployment.team).isEqualTo("HAAR team")
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
        mapOf("username" to "AUTH_ADM", "baseClientId" to "dctesty"),
        null,
      )
    }

    @Test
    fun `access forbidden when no authority`() {
      webTestClient.put().uri("/clients/testy/deployment")
        .body(
          BodyInserters.fromValue(
            mapOf(
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
    fun `unrecognised client id`() {
      webTestClient.put().uri("/clients/testy_unknown/deployment")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
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
        .expectStatus().isNotFound
        .expectBody()
        .json(
          """
              {
              "userMessage":"ClientDeployment for client id testy_unknown not found",
              "developerMessage":"ClientDeployment for client id testy_unknown not found"
              }
          """
            .trimIndent(),
        )
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.put().uri("/clients/testy/deployment")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .body(
          BodyInserters.fromValue(
            mapOf(
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
  }*/
}
