package uk.gov.justice.digital.hmpps.authorizationserver.integration

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.http.MediaType

class ClientsControllerIntTest : IntegrationTestBase() {

  @Nested
  inner class ListAllClients {
    @Test
    fun `access forbidden when no authority`() {
      webTestClient.get().uri("/clients/all")
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.get().uri("/clients/all")
        .headers(setAuthorisation(roles = listOf()))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.get().uri("/clients/all")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `list clients success`() {
      webTestClient.get().uri("/clients/all")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectHeader().contentType(MediaType.APPLICATION_JSON)
        .expectBody()
        .jsonPath("$.clients[4].baseClientId").isEqualTo("test-client-id")
        .jsonPath("$.clients[4].clientType").isEqualTo("PERSONAL")
        .jsonPath("$.clients[4].teamName").isEqualTo("HAAR")
        .jsonPath("$.clients[4].grantType").isEqualTo("client_credentials")
        .jsonPath("$.clients[4].roles").isEqualTo("AUDIT\nOAUTH_ADMIN\nTESTING")
        .jsonPath("$.clients[4].count").isEqualTo(1)
        .jsonPath("$.clients[4].expired").isEmpty
        .jsonPath("$.clients[*].baseClientId").value<List<String>> { assertThat(it).hasSize(5) }
        .jsonPath("$.clients[*].baseClientId").value<List<String>> {
          assertThat(it).containsAll(
            listOf(
              "ip-allow-a-client",
              "ip-allow-b-client",
              "ip-allow-c-client",
              "test-client-create-id",
              "test-client-id",
            ),
          )
        }
    }
  }
}
