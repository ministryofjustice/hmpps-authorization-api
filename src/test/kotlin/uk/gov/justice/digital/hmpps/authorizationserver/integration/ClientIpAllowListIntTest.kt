package uk.gov.justice.digital.hmpps.authorizationserver.integration

import org.junit.jupiter.api.Test
import java.util.Base64

class ClientIpAllowListIntTest : IntegrationTestBase() {

  @Test
  fun `empty ip allow list returns token`() {
    val username = "test-client-id"
    val token = "test-secret"
    webTestClient.post().uri("/oauth2/token?grant_type=client_credentials")
      .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("$username:$token").toByteArray()))
      .exchange()
      .expectStatus().isOk
  }

  @Test
  fun `localhost ip in allow list returns token`() {
    val username = "ip-allow-a-client-1"
    val token = "test-secret"
    webTestClient.post().uri("/oauth2/token?grant_type=client_credentials")
      .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("$username:$token").toByteArray()))
      .exchange()
      .expectStatus().isOk
  }

  @Test
  fun `ip in allow list base client id returns token`() {
    val username = "ip-allow-b-client"
    val token = "test-secret"
    webTestClient.post().uri("/oauth2/token?grant_type=client_credentials")
      .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("$username:$token").toByteArray()))
      .header("x-forwarded-for", "35.176.93.186")
      .exchange()
      .expectStatus().isOk
  }

  @Test
  fun `ip in allow list incremented client id returns token`() {
    val username = "ip-allow-b-client-8"
    val token = "test-secret"
    webTestClient.post().uri("/oauth2/token?grant_type=client_credentials")
      .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("$username:$token").toByteArray()))
      .header("x-forwarded-for", "35.176.93.186")
      .exchange()
      .expectStatus().isOk
  }

  // TODO BAD_REQUEST seems to be default response code in the event of any OAuth2AuthenticationException - is this correct?
  // TODO Note that Auth currently responds with FORBIDDEN for these cases

  @Test
  fun `localhost ip not in allow list forbidden`() {
    val username = "ip-allow-b-client"
    val token = "test-secret"
    webTestClient.post().uri("/oauth2/token?grant_type=client_credentials")
      .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("$username:$token").toByteArray()))
      .exchange()
      .expectStatus().isBadRequest
  }

  @Test
  fun `base client id ip not in allow list forbidden`() {
    val username = "ip-allow-b-client"
    val token = "test-secret"
    webTestClient.post().uri("/oauth2/token?grant_type=client_credentials")
      .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("$username:$token").toByteArray()))
      .header("x-forwarded-for", "235.177.93.186")
      .exchange()
      .expectStatus().isBadRequest
  }

  @Test
  fun `incremented client id ip not in allow list forbidden`() {
    val username = "ip-allow-b-client-8"
    val token = "test-secret"
    webTestClient.post().uri("/oauth2/token?grant_type=client_credentials")
      .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("$username:$token").toByteArray()))
      .header("x-forwarded-for", "235.177.93.186")
      .exchange()
      .expectStatus().isBadRequest
  }

  @Test
  fun `token can be retrieved when ip address uses CIDR notation in allow list`() {
    // TODO port last test case from Auth
  }
}
