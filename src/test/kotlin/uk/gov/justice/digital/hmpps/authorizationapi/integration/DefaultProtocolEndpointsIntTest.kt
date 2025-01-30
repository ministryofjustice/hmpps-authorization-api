package uk.gov.justice.digital.hmpps.authorizationapi.integration

import org.junit.jupiter.api.Test
import org.springframework.web.reactive.function.BodyInserters
import java.util.*

class DefaultProtocolEndpointsIntTest : IntegrationTestBase() {

  private val authorization: String = "Basic ${Base64.getEncoder().encodeToString(("test-client-id:test-secret").toByteArray())}"

  @Test
  fun `calling the default protocol endpoint device authorization is denied`() {
    webTestClient
      .post()
      .uri("/oauth2/device_authorization")
      .header("Authorization", authorization)
      .body(BodyInserters.fromFormData("client_id", "test-client-id"))
      .exchange()
      .expectStatus().isForbidden
  }

  @Test
  fun `calling the default protocol endpoint device verification is denied`() {
    webTestClient
      .post()
      .uri("/oauth2/device_verification")
      .header("Authorization", authorization)
      .body(BodyInserters.fromFormData("user_code", "JDTQ-CKTT"))
      .exchange()
      .expectStatus().isForbidden
  }

  @Test
  fun `calling the default protocol endpoint oauth2 introspect is denied`() {
    webTestClient
      .post()
      .uri("/oauth2/introspect")
      .header("Authorization", authorization)
      .body(BodyInserters.fromFormData("token", "test-token"))
      .exchange()
      .expectStatus().isForbidden
  }

  @Test
  fun `calling the default protocol endpoint oauth2 revoke is denied`() {
    webTestClient
      .post()
      .uri("/oauth2/revoke")
      .header("Authorization", authorization)
      .body(BodyInserters.fromFormData("token", "test-token"))
      .exchange()
      .expectStatus().isForbidden
  }
}
