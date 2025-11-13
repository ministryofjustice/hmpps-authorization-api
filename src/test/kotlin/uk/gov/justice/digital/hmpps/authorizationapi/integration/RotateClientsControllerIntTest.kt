package uk.gov.justice.digital.hmpps.authorizationapi.integration

import com.microsoft.applicationinsights.TelemetryClient
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.data.repository.findByIdOrNull
import org.springframework.http.HttpStatus
import org.springframework.test.context.bean.override.mockito.MockitoBean
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.AuthorizationConsent.AuthorizationConsentId
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.AuthorizationConsentRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientDeploymentRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientRepository
import uk.gov.justice.digital.hmpps.authorizationapi.utils.OAuthClientSecret
import java.util.Base64.getEncoder

class RotateClientsControllerIntTest : IntegrationTestBase() {

  @Autowired
  lateinit var clientConfigRepository: ClientConfigRepository

  @Autowired
  lateinit var clientRepository: ClientRepository

  @Autowired
  lateinit var authorizationConsentRepository: AuthorizationConsentRepository

  @Autowired
  lateinit var clientDeploymentRepository: ClientDeploymentRepository

  @MockitoBean
  lateinit var oAuthClientSecretGenerator: OAuthClientSecret

  @MockitoBean
  private lateinit var telemetryClient: TelemetryClient

  @Nested
  inner class DeleteClient {
    @Test
    fun `access unauthorized when no authority`() {
      webTestClient.delete().uri("/rotate/base-clients/test-client-id/clients/test-client-id")
        .exchange()
        .expectStatus().isUnauthorized
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.delete().uri("/rotate/base-clients/test-client-id/clients/test-client-id")
        .headers(setAuthorisation(roles = listOf()))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.delete().uri("/rotate/base-clients/test-client-id/clients/test-client-id")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `unrecognised client id`() {
      webTestClient.delete().uri("/rotate/base-clients/test-test-xyz/clients/test-test-xyz")
        .headers(setAuthorisation(roles = listOf("ROLE_CLIENT_ROTATION_ADMIN")))
        .exchange()
        .expectStatus().isNotFound
    }

    @Test
    fun `delete success single client version only`() {
      webTestClient.delete().uri("/rotate/base-clients/test-one-instance/clients/test-one-instance")
        .headers(setAuthorisation(roles = listOf("ROLE_CLIENT_ROTATION_ADMIN")))
        .exchange()
        .expectStatus().isOk

      assertNull(clientRepository.findClientByClientId("test-one-instance"))
      assertNull(clientDeploymentRepository.findClientDeploymentByBaseClientId("test-one-instance"))
      assertFalse(clientConfigRepository.findById("test-one-instance").isPresent)

      verify(telemetryClient).trackEvent(
        "AuthorizationApiClientDeleted",
        mapOf("username" to "AUTH_ADM", "clientId" to "test-one-instance"),
        null,
      )
    }

    @Test
    fun `delete success multiple client versions`() {
      assertNotNull(clientRepository.findClientByClientId("test-test"))
      assertNotNull(clientRepository.findClientByClientId("test-test-1"))

      webTestClient.delete().uri("/rotate/base-clients/test-test/clients/test-test-1")
        .headers(setAuthorisation(roles = listOf("ROLE_CLIENT_ROTATION_ADMIN")))
        .exchange()
        .expectStatus().isOk

      assertNull(clientRepository.findClientByClientId("test-test-1"))

      val baseClient = clientRepository.findClientByClientId("test-test")
      val clientDeployment = clientDeploymentRepository.findClientDeploymentByBaseClientId("test-test")
      val clientConfig = clientConfigRepository.findById("test-test")

      assertNotNull(baseClient)
      assertNotNull(clientDeployment)
      assertTrue(clientConfig.isPresent)

      clientDeploymentRepository.delete(clientDeployment)
      clientConfigRepository.delete(clientConfig.get())
      clientRepository.delete(baseClient)

      verify(telemetryClient).trackEvent(
        "AuthorizationApiClientDeleted",
        mapOf("username" to "AUTH_ADM", "clientId" to "test-test-1"),
        null,
      )
    }
  }

  @Nested
  inner class DuplicateClient {

    @Test
    fun `access unauthorized when no authority`() {
      webTestClient.post().uri("/rotate/base-clients/test-client-id/clients")
        .exchange()
        .expectStatus().isUnauthorized
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.post().uri("/rotate/base-clients/test-client-id/clients")
        .headers(setAuthorisation(roles = listOf()))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.post().uri("/rotate/base-clients/test-client-id/clients")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `not found when no clients exist for base client id`() {
      webTestClient.post().uri("/rotate/base-clients/test-client-x-id/clients")
        .headers(setAuthorisation(roles = listOf("ROLE_CLIENT_ROTATION_ADMIN")))
        .exchange()
        .expectStatus().isNotFound
    }

    @Test
    fun `conflict when the maximum number of clients already exist for base client id`() {
      whenever(oAuthClientSecretGenerator.generate())
        .thenReturn("external-client-secret")
        .thenReturn("external-client-secret-2")
        .thenReturn("external-client-secret-3")

      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret-2")).thenReturn("encoded-client-secret-2")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret-3")).thenReturn("encoded-client-secret-3")

      webTestClient.post().uri("/rotate/base-clients/test-client-id/clients")
        .headers(setAuthorisation(roles = listOf("ROLE_CLIENT_ROTATION_ADMIN")))
        .exchange()
        .expectStatus().isOk

      webTestClient.post().uri("/rotate/base-clients/test-client-id/clients")
        .headers(setAuthorisation(roles = listOf("ROLE_CLIENT_ROTATION_ADMIN")))
        .exchange()
        .expectStatus().isOk

      val duplicatedClient = clientRepository.findClientByClientId("test-client-id-1")
      val duplicatedClient2 = clientRepository.findClientByClientId("test-client-id-2")

      webTestClient.post().uri("/rotate/base-clients/test-client-id/clients")
        .headers(setAuthorisation(roles = listOf("ROLE_CLIENT_ROTATION_ADMIN")))
        .exchange()
        .expectStatus().isEqualTo(HttpStatus.CONFLICT)

      clientRepository.delete(duplicatedClient)
      clientRepository.delete(duplicatedClient2)
    }

    @Test
    fun `duplicate success`() {
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      webTestClient.post().uri("/rotate/base-clients/test-client-id/clients")
        .headers(setAuthorisation(roles = listOf("ROLE_CLIENT_ROTATION_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("clientId").isEqualTo("test-client-id-1")
        .jsonPath("clientSecret").isEqualTo("external-client-secret")
        .jsonPath("base64ClientId").isEqualTo(getEncoder().encodeToString("test-client-id-1".toByteArray()))
        .jsonPath("base64ClientSecret").isEqualTo(getEncoder().encodeToString("external-client-secret".toByteArray()))

      val originalClient = clientRepository.findClientByClientId("test-client-id")
      val duplicatedClient = clientRepository.findClientByClientId("test-client-id-1")
      assertThat(duplicatedClient!!.clientName).isEqualTo(originalClient!!.clientName)
      assertThat(duplicatedClient.scopes).isEqualTo(originalClient.scopes)
      assertThat(duplicatedClient.authorizationGrantTypes).isEqualTo(originalClient.authorizationGrantTypes)
      assertThat(duplicatedClient.clientAuthenticationMethods).isEqualTo(originalClient.clientAuthenticationMethods)
      assertThat(duplicatedClient.clientSettings).isEqualTo(originalClient.clientSettings)
      assertThat(duplicatedClient.tokenSettings).isEqualTo(originalClient.tokenSettings)

      val authorizationConsent = authorizationConsentRepository.findByIdOrNull(AuthorizationConsentId(originalClient.id, originalClient.clientId))
      val duplicateCateAuthorizationConsent = authorizationConsentRepository.findByIdOrNull(AuthorizationConsentId(duplicatedClient.id, duplicatedClient.clientId))

      assertThat(duplicateCateAuthorizationConsent?.authorities).isEqualTo(authorizationConsent?.authorities)

      authorizationConsentRepository.delete(duplicateCateAuthorizationConsent)

      verify(telemetryClient).trackEvent(
        "AuthorizationApiClientDetailsDuplicated",
        mapOf("username" to "AUTH_ADM", "clientId" to "test-client-id-1"),
        null,
      )

      clientRepository.delete(duplicatedClient)
    }
  }

  @Nested
  inner class ViewClientDeployment {

    @Test
    fun `access unauthorized when no authority`() {
      webTestClient.get().uri("/rotate/base-clients/testy")
        .exchange()
        .expectStatus().isUnauthorized
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.get().uri("/rotate/base-clients/testy/deployment")
        .headers(setAuthorisation(roles = listOf()))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.get().uri("/rotate/base-clients/testy/deployment")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `not found`() {
      webTestClient.get().uri("/rotate/base-clients/not-found/deployment")
        .headers(setAuthorisation(roles = listOf("ROLE_CLIENT_ROTATION_ADMIN")))
        .exchange()
        .expectStatus().isNotFound
    }

    @Test
    fun `view client deployment success`() {
      webTestClient.get().uri("/rotate/base-clients/test-client-id/deployment")
        .headers(setAuthorisation(roles = listOf("ROLE_CLIENT_ROTATION_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("deployment.clientType").isEqualTo("PERSONAL")
        .jsonPath("deployment.team").isEqualTo("HAAR")
        .jsonPath("deployment.teamContact").isEqualTo("Testy McTester")
        .jsonPath("deployment.teamSlack").isEqualTo("#hmpps-auth-audit-registers")
        .jsonPath("deployment.hosting").isEqualTo("CLOUDPLATFORM")
        .jsonPath("deployment.namespace").isEqualTo("hmpps-audit-dev")
        .jsonPath("deployment.deployment").isEqualTo("hmpps-audit-dev")
        .jsonPath("deployment.secretName").isEqualTo("AUDIT_SECRET")
        .jsonPath("deployment.clientIdKey").isEqualTo("AUDIT_API_KEY")
        .jsonPath("deployment.secretKey").isEqualTo("AUDIT_SECRET_KEY")
        .jsonPath("deployment.deploymentInfo").isEmpty
    }
  }
}
