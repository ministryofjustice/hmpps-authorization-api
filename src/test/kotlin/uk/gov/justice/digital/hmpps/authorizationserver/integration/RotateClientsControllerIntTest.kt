package uk.gov.justice.digital.hmpps.authorizationserver.integration

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
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.data.repository.findByIdOrNull
import org.springframework.http.HttpStatus
import org.springframework.web.reactive.function.BodyInserters
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.AuthorizationConsent
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.AuthorizationConsent.AuthorizationConsentId
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.AuthorizationConsentRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientDeploymentRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientRepository
import uk.gov.justice.digital.hmpps.authorizationserver.utils.OAuthClientSecret
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

  @MockBean
  lateinit var oAuthClientSecretGenerator: OAuthClientSecret

  @MockBean
  private lateinit var telemetryClient: TelemetryClient

  @Nested
  inner class DeleteClient {
    @Test
    fun `access forbidden when no authority`() {
      webTestClient.delete().uri("/rotate/base-clients/test-client-id/clients/test-client-id")
        .exchange()
        .expectStatus().isForbidden
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
      webTestClient.delete().uri("/rotate/base-clients/test-test/clients/test-test")
        .headers(setAuthorisation(roles = listOf("ROLE_CLIENT_ROTATION_ADMIN")))
        .exchange()
        .expectStatus().isNotFound
    }

    @Test
    fun `delete success single client version only`() {
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")
      givenANewClientExistsWithClientId("test-test")

      webTestClient.delete().uri("/rotate/base-clients/test-test/clients/test-test")
        .headers(setAuthorisation(roles = listOf("ROLE_CLIENT_ROTATION_ADMIN")))
        .exchange()
        .expectStatus().isOk

      assertNull(clientRepository.findClientByClientId("test-test"))
      assertNull(clientDeploymentRepository.findClientDeploymentByBaseClientId("test-test"))
      assertFalse(clientConfigRepository.findById("test-test").isPresent)

      verify(telemetryClient).trackEvent(
        "AuthorizationServerClientDeleted",
        mapOf("username" to "AUTH_ADM", "clientId" to "test-test"),
        null,
      )
    }

    @Test
    fun `delete success multiple client versions`() {
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret").thenReturn("external-client-secret-2")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret-2")).thenReturn("encoded-client-secret-2")

      givenANewClientExistsWithClientId("test-test")

      webTestClient.post().uri("/base-clients/test-test/clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk

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
        "AuthorizationServerClientDeleted",
        mapOf("username" to "AUTH_ADM", "clientId" to "test-test-1"),
        null,
      )
    }

    private fun givenANewClientExistsWithClientId(clientId: String) {
      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to clientId,
              "grantType" to "client_credentials",
              "clientName" to "testing testing",
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testy-mctest-1",
              "jiraNumber" to "HAAR-9999",
              "validDays" to 5,
              "accessTokenValidity" to 20,
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      webTestClient.put().uri("/base-clients/$clientId/deployment")
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
        .expectStatus().isOk

      assertNotNull(clientRepository.findClientByClientId("test-test"))
      assertNotNull(clientDeploymentRepository.findClientDeploymentByBaseClientId("test-test"))
      assertTrue(clientConfigRepository.findById("test-test").isPresent)
    }
  }

  @Nested
  inner class DuplicateClient {

    @Test
    fun `access forbidden when no authority`() {
      webTestClient.post().uri("/rotate/base-clients/test-client-id/clients")
        .exchange()
        .expectStatus().isForbidden
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
        "AuthorizationServerClientDetailsDuplicated",
        mapOf("username" to "AUTH_ADM", "clientId" to "test-client-id-1"),
        null,
      )

      clientRepository.delete(duplicatedClient)
    }
  }

  @Nested
  inner class ViewClient {

    @Test
    fun `access forbidden when no authority`() {
      webTestClient.get().uri("/rotate/base-clients/testy")
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.get().uri("/rotate/base-clients/testy")
        .headers(setAuthorisation(roles = listOf()))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.get().uri("/rotate/base-clients/testy")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `not found`() {
      webTestClient.get().uri("/rotate/base-clients/not-found")
        .headers(setAuthorisation(roles = listOf("ROLE_CLIENT_ROTATION_ADMIN")))
        .exchange()
        .expectStatus().isNotFound
    }

    @Test
    fun `view client success`() {
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "test-more-test",
              "grantType" to "client_credentials",
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testy-more-mctest-1",
              "jiraNumber" to "HAAR-7777",
              "validDays" to 5,
              "accessTokenValidityMinutes" to 20,
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      webTestClient.put().uri("/base-clients/test-more-test/deployment")
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
        .expectStatus().isOk

      webTestClient.get().uri("/rotate/base-clients/test-more-test")
        .headers(setAuthorisation(roles = listOf("ROLE_CLIENT_ROTATION_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("clientId").isEqualTo("test-more-test")
        .jsonPath("scopes[0]").isEqualTo("read")
        .jsonPath("scopes[1]").isEqualTo("write")
        .jsonPath("authorities[0]").isEqualTo("ROLE_CURIOUS_API")
        .jsonPath("authorities[1]").isEqualTo("ROLE_VIEW_PRISONER_DATA")
        .jsonPath("authorities[2]").isEqualTo("ROLE_COMMUNITY")
        .jsonPath("ips[0]").isEqualTo("81.134.202.29/32")
        .jsonPath("ips[1]").isEqualTo("35.176.93.186/32")
        .jsonPath("jiraNumber").isEqualTo("HAAR-7777")
        .jsonPath("validDays").isEqualTo(5)
        .jsonPath("accessTokenValidityMinutes").isEqualTo(20)
        .jsonPath("deployment.clientType").isEqualTo("PERSONAL")
        .jsonPath("deployment.team").isEqualTo("testing team")
        .jsonPath("deployment.teamContact").isEqualTo("testy lead")
        .jsonPath("deployment.teamSlack").isEqualTo("#testy")
        .jsonPath("deployment.hosting").isEqualTo("CLOUDPLATFORM")
        .jsonPath("deployment.namespace").isEqualTo("testy-testing-dev")
        .jsonPath("deployment.deployment").isEqualTo("hmpps-testing-dev")
        .jsonPath("deployment.secretName").isEqualTo("hmpps-testing")
        .jsonPath("deployment.clientIdKey").isEqualTo("SYSTEM_CLIENT_ID")
        .jsonPath("deployment.secretKey").isEqualTo("SYSTEM_CLIENT_SECRET")
        .jsonPath("deployment.deploymentInfo").isEmpty

      val client = clientRepository.findClientByClientId("test-more-test")
      val clientConfig = clientConfigRepository.findById(client!!.clientId).get()
      val authorizationConsent = authorizationConsentRepository.findById(AuthorizationConsent.AuthorizationConsentId(client.id, client.clientId)).get()
      clientRepository.delete(client)
      clientConfigRepository.delete(clientConfig)
      authorizationConsentRepository.delete(authorizationConsent)
    }

    @Test
    fun `view incomplete client success`() {
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "test-more-test",
              "grantType" to "client_credentials",
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      webTestClient.get().uri("/rotate/base-clients/test-more-test")
        .headers(setAuthorisation(roles = listOf("ROLE_CLIENT_ROTATION_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("clientId").isEqualTo("test-more-test")
        .jsonPath("scopes[0]").isEqualTo("read")

      val client = clientRepository.findClientByClientId("test-more-test")
      assertNull(clientConfigRepository.findByIdOrNull(client!!.clientId))
      assertNull(authorizationConsentRepository.findByIdOrNull(AuthorizationConsent.AuthorizationConsentId(client.id, client.clientId)))
      clientRepository.delete(client)
    }
  }
}
