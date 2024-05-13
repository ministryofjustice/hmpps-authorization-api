package uk.gov.justice.digital.hmpps.authorizationapi.integration

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.http.MediaType

class ClientsDataControllerIntTest : IntegrationTestBase() {

  @Nested
  inner class ListAllClientDetails {
    @Test
    fun `access unauthorized when no authority`() {
      webTestClient.get().uri("/client-details")
        .exchange()
        .expectStatus().isUnauthorized
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.get().uri("/client-details")
        .headers(setAuthorisation(roles = listOf()))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.get().uri("/client-details")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `list client details success`() {
      val matchByClientId = "$[?(@.clientId == '%s')]"
      webTestClient.get().uri("/client-details")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectHeader().contentType(MediaType.APPLICATION_JSON)
        .expectBody()
        .jsonPath("$.[*]").value<List<String>> { assertThat(it).hasSize(10) }
        .jsonPath("\$.[0].clientId").isEqualTo("test-client-id")
        .jsonPath("\$.[0].scopes[0]").isEqualTo("read")
        .jsonPath("\$.[0].scopes[1]").isEqualTo("write")
        .jsonPath("\$.[0].skipToAzure").isBoolean
        .jsonPath("\$.[0].mfaRememberMe").isBoolean
        .jsonPath("\$.[0].ips").doesNotExist()
        .jsonPath("\$.[0].authorities[*]").value<List<String>> {
          assertThat(it)
            .containsExactlyInAnyOrder("ROLE_OAUTH_ADMIN", "ROLE_AUDIT", "ROLE_TESTING", "ROLE_VIEW_AUTH_SERVICE_DETAILS")
        }
        .jsonPath("\$.[2].ips[*]").value<List<String>> {
          assertThat(it)
            .containsExactlyInAnyOrder("127.0.0.1/32")
        }
        .jsonPath(matchByClientId, "test-client-id").exists()
        .jsonPath(matchByClientId, "test-client-create-id").exists()
        .jsonPath(matchByClientId, "ip-allow-a-client-1").exists()
        .jsonPath(matchByClientId, "ip-allow-b-client").exists()
        .jsonPath(matchByClientId, "ip-allow-b-client-8").exists()
        .jsonPath(matchByClientId, "test-duplicate-id").exists()
        .jsonPath(matchByClientId, "test-complete-details-id").exists()
        .jsonPath(matchByClientId, "ip-allow-c-client").exists()
        .jsonPath(matchByClientId, "test-auth-code-client").exists()
        .jsonPath(matchByClientId, "hmpps-auth-authorization-api-client").exists()
    }
  }
}
