package uk.gov.justice.digital.hmpps.authorizationapi.integration

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.http.MediaType
import java.time.LocalDateTime

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
        .jsonPath("$.[*]").value<List<String>> { assertThat(it).hasSize(162) }
        .jsonPath("$.[0].clientId").isEqualTo("test-client-id")
        .jsonPath("$.[0].scopes[0]").isEqualTo("read")
        .jsonPath("$.[0].scopes[1]").isEqualTo("write")
        .jsonPath("$.[0].skipToAzure").isBoolean
        .jsonPath("$.[0].mfaRememberMe").isBoolean
        .jsonPath("$.[0].ips").doesNotExist()
        .jsonPath("$.[0].redirectUris").doesNotExist()
        .jsonPath("$.[0].authorities[*]").value<List<String>> {
          assertThat(it)
            .containsExactlyInAnyOrder(
              "ROLE_OAUTH_ADMIN",
              "ROLE_AUDIT",
              "ROLE_TESTING",
              "ROLE_VIEW_AUTH_SERVICE_DETAILS",
            )
        }
        .jsonPath("$.[2].ips[*]").value<List<String>> {
          assertThat(it)
            .containsExactlyInAnyOrder("127.0.0.1/32")
        }
        .jsonPath(String.format(matchByClientId, "test-client-id")).exists()
        .jsonPath(String.format(matchByClientId, "test-client-create-id")).exists()
        .jsonPath(String.format(matchByClientId, "ip-allow-a-client-1")).exists()
        .jsonPath(String.format(matchByClientId, "ip-allow-b-client")).exists()
        .jsonPath(String.format(matchByClientId, "ip-allow-b-client-8")).exists()
        .jsonPath(String.format(matchByClientId, "test-duplicate-id")).exists()
        .jsonPath(String.format(matchByClientId, "test-complete-details-id")).exists()
        .jsonPath(String.format(matchByClientId, "ip-allow-c-client")).exists()
        .jsonPath(String.format(matchByClientId, "test-auth-code-client")).exists()
        .jsonPath(String.format(matchByClientId, "hmpps-auth-authorization-api-client")).exists()
        .jsonPath(String.format(matchByClientId, "expiry-test-client")).exists()
        .jsonPath("$.[0].expired").isEqualTo(false)
        .jsonPath("$.[1].expired").isEqualTo(false)
        .jsonPath("$.[2].expired").isEqualTo(false)
        .jsonPath("$.[3].expired").isEqualTo(false)
        .jsonPath("$.[4].expired").isEqualTo(false)
        .jsonPath("$.[5].expired").isEqualTo(false)
        .jsonPath("$.[6].expired").isEqualTo(false)
        .jsonPath("$.[7].expired").isEqualTo(false)
        .jsonPath("$.[8].expired").isEqualTo(false)
        .jsonPath("$.[8].redirectUris[*]").value<List<String>> {
          assertThat(it)
            .containsExactlyInAnyOrder(
              "http://127.0.0.1:8089/login/oauth2/code/oidc-client",
              "https://oauth.pstmn.io/v1/callback",
            )
        }
        .jsonPath("$.[9].expired").isEqualTo(false)
        .jsonPath("$.[10].expired").isEqualTo(false)
        .jsonPath("$.[11].expired").isEqualTo(true)
    }
  }

  @Nested
  inner class GetAllClientsWithLastAccessed {
    @Test
    fun `access unauthorized when no authority`() {
      webTestClient.get().uri("/client-details-last-accessed")
        .exchange()
        .expectStatus().isUnauthorized
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.get().uri("/client-details-last-accessed")
        .headers(setAuthorisation(roles = listOf()))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.get().uri("/client-details-last-accessed")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `get clients details with last accessed success`() {
      webTestClient.get().uri("/client-details-last-accessed")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectHeader().contentType(MediaType.APPLICATION_JSON)
        .expectBody()
        .jsonPath("$.[*]").value<List<String>> { assertThat(it).hasSize(162) }
        .jsonPath("$.[0].clientId").isEqualTo("test-client-id")
        .jsonPath("$.[0].lastAccessed").isEqualTo("2024-08-22T11:30:30")
        .jsonPath("$.[1].clientId").isEqualTo("test-client-create-id")
        .jsonPath("$.[1].lastAccessed").value { lastAccessed: String ->
          val lastAccessedTime = LocalDateTime.parse(lastAccessed)
          val now = LocalDateTime.now()
          assertThat(lastAccessedTime).isBetween(now.minusMinutes(1), now)
        }
    }
  }
}
