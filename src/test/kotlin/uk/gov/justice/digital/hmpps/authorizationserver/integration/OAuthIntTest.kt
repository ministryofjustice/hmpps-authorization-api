package uk.gov.justice.digital.hmpps.authorizationserver.integration

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Base64

class OAuthIntTest : IntegrationTestBase() {

  @Test
  fun `client credentials login`() {
    webTestClient
      .post().uri("/oauth2/token?grant_type=client_credentials")
      .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("test-client-id:test-secret").toByteArray()))
      .exchange()
      .expectStatus().isOk
      .expectBody()
      .jsonPath("$").value<Map<String, Any>> {
        assertThat(it).containsKey("expires_in")
        assertThat(it["expires_in"] as Int).isLessThan(3600)
        assertThat(it).doesNotContainKey("refreshToken")
      }
  }

  @Test
  fun `client credentials login - incorrect secret`() {
    webTestClient
      .post().uri("/oauth2/token?grant_type=client_credentials")
      .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("test-client-id:test-secretx").toByteArray()))
      .exchange()
      .expectStatus().isUnauthorized
  }

  @Test
  fun `client credentials login - unrecognised client id`() {
    webTestClient
      .post().uri("/oauth2/token?grant_type=client_credentials")
      .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("unrecognised-client-id:test-secret").toByteArray()))
      .exchange()
      .expectStatus().isUnauthorized
  }
}
