package uk.gov.justice.digital.hmpps.authorizationapi.integration

import com.microsoft.applicationinsights.TelemetryClient
import org.assertj.core.api.Assertions.assertThat
import org.hamcrest.CoreMatchers
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.verify
import org.mockito.kotlin.verifyNoInteractions
import org.mockito.kotlin.whenever
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.data.repository.findByIdOrNull
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.web.reactive.function.BodyInserters
import uk.gov.justice.digital.hmpps.authorizationapi.adapter.AuthService
import uk.gov.justice.digital.hmpps.authorizationapi.adapter.ServiceDetails
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.AuthorizationConsent
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.AuthorizationConsent.AuthorizationConsentId
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.ClientType
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.Hosting
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.MfaAccess
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.AuthorizationConsentRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientDeploymentRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientRepository
import uk.gov.justice.digital.hmpps.authorizationapi.resource.GrantType
import uk.gov.justice.digital.hmpps.authorizationapi.service.RegisteredClientAdditionalInformation
import uk.gov.justice.digital.hmpps.authorizationapi.utils.OAuthClientSecret
import java.time.Duration
import java.time.LocalDate
import java.util.Base64.getEncoder
import java.util.Optional

class ClientsInterfaceControllerIntTest : IntegrationTestBase() {

  @Autowired
  lateinit var clientConfigRepository: ClientConfigRepository

  @Autowired
  lateinit var registeredClientAdditionalInformation: RegisteredClientAdditionalInformation

  @Autowired
  lateinit var clientRepository: ClientRepository

  @Autowired
  lateinit var authorizationConsentRepository: AuthorizationConsentRepository

  @Autowired
  lateinit var clientDeploymentRepository: ClientDeploymentRepository

  @MockBean
  lateinit var oAuthClientSecretGenerator: OAuthClientSecret

  @MockBean
  lateinit var authService: AuthService

  @MockBean
  private lateinit var telemetryClient: TelemetryClient

  @Autowired
  lateinit var jdbcRegisteredClientRepository: JdbcRegisteredClientRepository

  @Nested
  inner class ListAllClients {
    @Test
    fun `access unauthorized when no authority`() {
      webTestClient.get().uri("/base-clients")
        .exchange()
        .expectStatus().isUnauthorized
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.get().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf()))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.get().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `list clients success`() {
      webTestClient.get().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectHeader().contentType(MediaType.APPLICATION_JSON)
        .expectBody()
        .jsonPath("$.clients[0].baseClientId").isEqualTo("expiry-test-client")
        .jsonPath("$.clients[0].expired").isEqualTo("EXPIRED")
        .jsonPath("$.clients[7].baseClientId").isEqualTo("test-client-create-id")
        .jsonPath("$.clients[7].clientType").isEqualTo("PERSONAL")
        .jsonPath("$.clients[7].teamName").isEqualTo("HAAR")
        .jsonPath("$.clients[7].grantType").isEqualTo("client_credentials")
        .jsonPath("$.clients[7].roles").isEqualTo(
          "AUDIT\n" +
            "OAUTH_ADMIN\nTESTING\nVIEW_AUTH_SERVICE_DETAILS",
        )
        .jsonPath("$.clients[6].count").isEqualTo(1)
        .jsonPath("$.clients[6].expired").isEmpty
        .jsonPath("\$.clients[8].baseClientId").isEqualTo("test-client-id")
        .jsonPath("\$.clients[8].lastAccessed").isEqualTo("2024-08-22T10:30:30Z")
        .jsonPath("\$.clients[5].baseClientId").isEqualTo("test-auth-code-client")
        .jsonPath("\$.clients[5].lastAccessed").isEqualTo("2024-08-19T17:36:27Z")
        .jsonPath("$.clients[*].baseClientId").value<List<String>> { assertThat(it).hasSize(13) }
        .jsonPath("$.clients[*].baseClientId").value<List<String>> {
          assertThat(it).containsAll(
            listOf(
              "expiry-test-client",
              "hmpps-auth-authorization-api-client",
              "ip-allow-a-client",
              "ip-allow-b-client",
              "ip-allow-c-client",
              "test-auth-code-client",
              "test-auth-code-client-with-jwt-settings",
              "test-client-create-id",
              "test-client-id",
              "test-complete-details-id",
              "test-duplicate-id",
              "url-encode-auth-code",
              "url-encode-client-credentials",
            ),
          )
        }
    }

    @Test
    fun `list clients filtered by roles, grantType and clientType`() {
      webTestClient.get().uri("/base-clients?role=AUDIT&grantType=client_credentials&clientType=PERSONAL")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectHeader().contentType(MediaType.APPLICATION_JSON)
        .expectBody()
        .jsonPath("$.clients[0].baseClientId").isEqualTo("test-client-create-id")
        .jsonPath("$.clients[0].clientType").isEqualTo("PERSONAL")
        .jsonPath("$.clients[0].teamName").isEqualTo("HAAR")
        .jsonPath("$.clients[0].grantType").isEqualTo("client_credentials")
        .jsonPath("$.clients[0].roles").isEqualTo(
          "AUDIT\n" +
            "OAUTH_ADMIN\nTESTING\nVIEW_AUTH_SERVICE_DETAILS",
        )
        .jsonPath("$.clients[0].count").isEqualTo(1)
        .jsonPath("$.clients[0].expired").isEmpty
        .jsonPath("$.clients[*].baseClientId").value<List<String>> { assertThat(it).hasSize(2) }
        .jsonPath("$.clients[*].baseClientId").value<List<String>> {
          assertThat(it).containsAll(
            listOf(
              "test-client-id",
              "test-client-create-id",
            ),
          )
        }
    }
  }

  @Nested
  inner class DeleteClient {
    @Test
    fun `access unauthorized when no authority`() {
      webTestClient.delete().uri("/base-clients/test-client-id/clients/test-client-id")
        .exchange()
        .expectStatus().isUnauthorized
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.delete().uri("/base-clients/test-client-id/clients/test-client-id")
        .headers(setAuthorisation(roles = listOf()))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.delete().uri("/base-clients/test-client-id/clients/test-client-id")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `unrecognised client id`() {
      webTestClient.delete().uri("/base-clients/test-test/clients/test-test")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isNotFound
    }

    @Test
    fun `delete success single client version only`() {
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")
      givenANewClientExistsWithClientId("test-test")

      webTestClient.delete().uri("/base-clients/test-test/clients/test-test")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk

      assertNull(clientRepository.findClientByClientId("test-test"))
      assertNull(clientDeploymentRepository.findClientDeploymentByBaseClientId("test-test"))
      assertFalse(clientConfigRepository.findById("test-test").isPresent)

      verify(telemetryClient).trackEvent(
        "AuthorizationApiClientDeleted",
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

      webTestClient.delete().uri("/base-clients/test-test/clients/test-test-1")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
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
  inner class ListCopies {
    @Test
    fun `access unauthorized when no authority`() {
      webTestClient.get().uri("/base-clients/test-client-id/clients")
        .exchange()
        .expectStatus().isUnauthorized
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.get().uri("/base-clients/test-client-id/clients")
        .headers(setAuthorisation(roles = listOf()))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.get().uri("/base-clients/test-client-id/clients")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `unrecognised client id`() {
      webTestClient.get().uri("/base-clients/test-test/clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isNotFound
    }

    @Test
    fun `lists multiple copies ordered by client id`() {
      webTestClient.get().uri("/base-clients/ip-allow-b-client-8/clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("$.clients[*].clientId").value<List<String>> { assertThat(it).hasSize(2) }
        .jsonPath("$.clients[*].clientId").value<List<String>> {
          assertThat(it).containsExactly(
            "ip-allow-b-client",
            "ip-allow-b-client-8",
          )
        }
        .jsonPath("$.clients[0].clientId").isEqualTo("ip-allow-b-client")
        .jsonPath("$.clients[0].created").isNotEmpty
        .jsonPath("$.clients[0].lastAccessed").isNotEmpty
    }

    @Test
    fun `returns single client when no other copies`() {
      webTestClient.get().uri("/base-clients/test-client-id/clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("$.clients[*].clientId").value<List<String>> { assertThat(it).hasSize(1) }
        .jsonPath("$.clients[*].clientId").value<List<String>> {
          assertThat(it).containsExactly(
            "test-client-id",
          )
        }
    }
  }

  @Nested
  inner class DuplicateClient {

    @Test
    fun `access unauthorized when no authority`() {
      webTestClient.post().uri("/base-clients/test-client-id/clients")
        .exchange()
        .expectStatus().isUnauthorized
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.post().uri("/base-clients/test-client-id/clients")
        .headers(setAuthorisation(roles = listOf()))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.post().uri("/base-clients/test-client-id/clients")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `not found when no clients exist for base client id`() {
      webTestClient.post().uri("/base-clients/test-client-x-id/clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
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

      webTestClient.post().uri("/base-clients/test-client-id/clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk

      webTestClient.post().uri("/base-clients/test-client-id/clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk

      val duplicatedClient = clientRepository.findClientByClientId("test-client-id-1")
      val duplicatedClient2 = clientRepository.findClientByClientId("test-client-id-2")

      webTestClient.post().uri("/base-clients/test-client-id/clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isEqualTo(HttpStatus.CONFLICT)

      clientRepository.delete(duplicatedClient)
      clientRepository.delete(duplicatedClient2)
    }

    @Test
    fun `duplicate success`() {
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      webTestClient.post().uri("/base-clients/test-client-id/clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
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
      assertThat(registeredClientAdditionalInformation.getJiraNumber(duplicatedClient.clientSettings)).isEqualTo(registeredClientAdditionalInformation.getJiraNumber(originalClient.clientSettings))
      assertThat(registeredClientAdditionalInformation.getDatabaseUserName(duplicatedClient.clientSettings)).isEqualTo(registeredClientAdditionalInformation.getDatabaseUserName(originalClient.clientSettings))

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

    @Test
    fun `should be able to duplicate authorization code grant type client without redirect url`() {
      val clientId = "new-auth-client"
      whenever(oAuthClientSecretGenerator.generate()).thenReturn(clientId)
      whenever(oAuthClientSecretGenerator.encode(clientId)).thenReturn("encoded-client-secret")

      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to clientId,
              "grantType" to "authorization_code",
              "scopes" to listOf("read", "write"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testy-mctest",
              "jiraNumber" to "HAAR-9999",
              "validDays" to 5,
              "accessTokenValiditySeconds" to 20,
              "jwtFields" to "-name",
              "mfaRememberMe" to true,
              "mfa" to MfaAccess.ALL,
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("clientId").isEqualTo(clientId)
        .jsonPath("clientSecret").isEqualTo("new-auth-client")
        .jsonPath("base64ClientId").isEqualTo(getEncoder().encodeToString(clientId.toByteArray()))
        .jsonPath("base64ClientSecret").isEqualTo(getEncoder().encodeToString("new-auth-client".toByteArray()))

      whenever(oAuthClientSecretGenerator.generate()).thenReturn("new-auth-client-1")
      whenever(oAuthClientSecretGenerator.encode("new-auth-client-1")).thenReturn("new-auth-client-1")
      webTestClient.post().uri("/base-clients/new-auth-client/clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("clientId").isEqualTo("new-auth-client-1")
        .jsonPath("clientSecret").isEqualTo("new-auth-client-1")
        .jsonPath("base64ClientId").isEqualTo(getEncoder().encodeToString("new-auth-client-1".toByteArray()))
        .jsonPath("base64ClientSecret").isEqualTo(getEncoder().encodeToString("new-auth-client-1".toByteArray()))

      val originalClient = clientRepository.findClientByClientId("new-auth-client")
      val duplicatedClient = clientRepository.findClientByClientId("new-auth-client-1")
      assertThat(duplicatedClient!!.clientName).isEqualTo(originalClient!!.clientName)
      assertThat(duplicatedClient.redirectUris).isNull()
      assertThat(duplicatedClient.authorizationGrantTypes).isEqualTo(originalClient.authorizationGrantTypes)
      assertThat(duplicatedClient.clientAuthenticationMethods).isEqualTo(originalClient.clientAuthenticationMethods)
      assertThat(duplicatedClient.clientSettings).isEqualTo(originalClient.clientSettings)
      assertThat(duplicatedClient.tokenSettings).isEqualTo(originalClient.tokenSettings)

      verify(telemetryClient).trackEvent(
        "AuthorizationApiClientDetailsDuplicated",
        mapOf("username" to "AUTH_ADM", "clientId" to "new-auth-client-1"),
        null,
      )

      clientRepository.delete(duplicatedClient)
      clientRepository.delete(originalClient)
    }
  }

  @Nested
  inner class AddClient {

    @Test
    fun `access unauthorized when no authority`() {
      webTestClient.post().uri("/base-clients")
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
              "grantType" to "client_credentials",
              "clientName" to "test client",
              "scopes" to listOf("read"),
              "authorities" to listOf("VIEW_PRISONER_DATA"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isUnauthorized
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf()))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
              "grantType" to "client_credentials",
              "clientName" to "test client",
              "scopes" to listOf("read"),
              "authorities" to listOf("VIEW_PRISONER_DATA"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
              "grantType" to "client_credentials",
              "clientName" to "test client",
              "scopes" to listOf("read"),
              "authorities" to listOf("VIEW_PRISONER_DATA"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `bad request when client already exists`() {
      assertNotNull(jdbcRegisteredClientRepository.findByClientId("test-client-id"))

      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "test-client-id",
              "grantType" to "client_credentials",
              "clientName" to "test client",
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isBadRequest
        .expectBody()
        .json(
          """
              {
              "userMessage":"Client with client id test-client-id cannot be created as already exists",
              "developerMessage":"Client with client id test-client-id cannot be created as already exists"
              }
          """
            .trimIndent(),
        )
    }

    @Test
    fun `bad request when client with same base client id already exists`() {
      assertNotNull(jdbcRegisteredClientRepository.findByClientId("ip-allow-a-client-1"))
      assertNull(jdbcRegisteredClientRepository.findByClientId("ip-allow-a-client"))

      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "ip-allow-a-client",
              "grantType" to "client_credentials",
              "clientName" to "test client",
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isBadRequest
        .expectBody()
        .json(
          """
              {
              "userMessage":"Client with client id ip-allow-a-client cannot be created as already exists",
              "developerMessage":"Client with client id ip-allow-a-client cannot be created as already exists"
              }
          """
            .trimIndent(),
        )
    }

    @Test
    fun `register client credentials client success`() {
      assertNull(clientRepository.findClientByClientId("testy"))
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
              "grantType" to "client_credentials",
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testy-mctest",
              "jiraNumber" to "HAAR-9999",
              "validDays" to 5,
              "accessTokenValiditySeconds" to 20,
              "skipToAzure" to true,
              "resourceIds" to listOf("resource-id1", "resource-id2"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("clientId").isEqualTo("testy")
        .jsonPath("clientSecret").isEqualTo("external-client-secret")
        .jsonPath("base64ClientId").isEqualTo(getEncoder().encodeToString("testy".toByteArray()))
        .jsonPath("base64ClientSecret").isEqualTo(getEncoder().encodeToString("external-client-secret".toByteArray()))

      val client = clientRepository.findClientByClientId("testy")

      assertNotNull(client)
      assertThat(client!!.clientId).isEqualTo("testy")
      assertThat(client.clientName).isEqualTo("testy")
      assertThat(client.clientSecret).isEqualTo("encoded-client-secret")
      assertThat(client.authorizationGrantTypes).isEqualTo(GrantType.client_credentials.name)
      assertThat(client.scopes).contains("read", "write")
      assertThat(client.tokenSettings.accessTokenTimeToLive).isEqualTo(Duration.ofSeconds(20))
      assertThat(client.tokenSettings.authorizationCodeTimeToLive).isEqualTo(Duration.ofMinutes(5))
      assertThat(registeredClientAdditionalInformation.getDatabaseUserName(client.clientSettings)).contains("testy-mctest")
      assertThat(registeredClientAdditionalInformation.getJiraNumber(client.clientSettings)).isEqualTo("HAAR-9999")
      assertThat(client.skipToAzure).isTrue
      assertThat(client.resourceIds).contains("resource-id1")

      val clientConfig = clientConfigRepository.findById(client.clientId).get()
      assertThat(clientConfig.ips).contains("81.134.202.29/32", "35.176.93.186/32")
      assertThat(clientConfig.clientEndDate).isEqualTo(LocalDate.now().plusDays(4))
      val authorizationConsent =
        verifyAuthorities(client.id, client.clientId, "ROLE_CURIOUS_API", "ROLE_VIEW_PRISONER_DATA", "ROLE_COMMUNITY")

      verify(telemetryClient).trackEvent(
        "AuthorizationApiDetailsAdd",
        mapOf("username" to "AUTH_ADM", "clientId" to "testy", "grantType" to "client_credentials"),
        null,
      )

      clientRepository.delete(client)
      clientConfigRepository.delete(clientConfig)
      authorizationConsentRepository.delete(authorizationConsent)
    }

    @Test
    fun `register client credentials client without authorities`() {
      assertNull(clientRepository.findClientByClientId("testy"))
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
              "grantType" to "client_credentials",
              "scopes" to listOf("read", "write"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testy-mctest",
              "jiraNumber" to "HAAR-9999",
              "validDays" to 5,
              "accessTokenValiditySeconds" to 20,
              "skipToAzure" to true,
              "resourceIds" to listOf("resource-id1", "resource-id2"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      val client = clientRepository.findClientByClientId("testy")
      assertNotNull(client)
      val clientConfig = clientConfigRepository.findById(client!!.clientId).get()
      assertNotNull(clientConfig)
      verifyAuthorizationConsentRecordNotPresent(client.id, client.clientId)

      clientRepository.delete(client)
      clientConfigRepository.delete(clientConfig)
    }

    @Test
    fun `register authorization code client success`() {
      val clientId = "test-auth-code-client-id"
      assertNull(clientRepository.findClientByClientId(clientId))
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to clientId,
              "grantType" to "authorization_code",
              "scopes" to listOf("read", "write"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testy-mctest",
              "jiraNumber" to "HAAR-9999",
              "redirectUris" to "http://127.0.0.1:8089/authorized,https://oauth.pstmn.io/v1/callback",
              "validDays" to 5,
              "accessTokenValiditySeconds" to 20,
              "jwtFields" to "-name",
              "mfaRememberMe" to true,
              "mfa" to MfaAccess.ALL,
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("clientId").isEqualTo(clientId)
        .jsonPath("clientSecret").isEqualTo("external-client-secret")
        .jsonPath("base64ClientId").isEqualTo(getEncoder().encodeToString(clientId.toByteArray()))
        .jsonPath("base64ClientSecret").isEqualTo(getEncoder().encodeToString("external-client-secret".toByteArray()))

      val client = clientRepository.findClientByClientId(clientId)

      assertNotNull(client)
      assertThat(client!!.clientId).isEqualTo(clientId)
      assertThat(client.clientName).isEqualTo(clientId)
      assertThat(client.clientSecret).isEqualTo("encoded-client-secret")
      assertThat(client.authorizationGrantTypes).isEqualTo(GrantType.authorization_code.name)
      assertThat(client.scopes).contains("read", "write")
      assertThat(client.tokenSettings.accessTokenTimeToLive).isEqualTo(Duration.ofSeconds(20))
      assertThat(client.tokenSettings.accessTokenTimeToLive).isEqualTo(Duration.ofSeconds(20))
      assertThat(registeredClientAdditionalInformation.getJiraNumber(client.clientSettings)).isEqualTo("HAAR-9999")
      assertThat(registeredClientAdditionalInformation.getDatabaseUserName(client.clientSettings)).isEqualTo("testy-mctest")
      assertThat(registeredClientAdditionalInformation.getJwtFields(client.clientSettings)).isEqualTo("-name")
      assertThat(client.mfaRememberMe).isTrue
      assertThat(client.mfa).isEqualTo(MfaAccess.ALL)
      assertThat(client.redirectUris).isEqualTo("http://127.0.0.1:8089/authorized,https://oauth.pstmn.io/v1/callback")

      verifyAuthorizationConsentRecordNotPresent(client.id, client.clientId)

      val clientConfig = clientConfigRepository.findById(client.clientId).get()
      assertThat(clientConfig.ips).contains("81.134.202.29/32", "35.176.93.186/32")
      assertThat(clientConfig.clientEndDate).isEqualTo(LocalDate.now().plusDays(4))

      verify(telemetryClient).trackEvent(
        "AuthorizationApiDetailsAdd",
        mapOf("username" to "AUTH_ADM", "clientId" to clientId, "grantType" to "authorization_code"),
        null,
      )

      clientRepository.delete(client)
      clientConfigRepository.delete(clientConfig)
    }

    @Test
    fun `register incomplete client`() {
      assertNull(clientRepository.findClientByClientId("testy"))
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
              "grantType" to "client_credentials",
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("clientId").isEqualTo("testy")
        .jsonPath("clientSecret").isEqualTo("external-client-secret")

      val client = clientRepository.findClientByClientId("testy")

      assertNotNull(client)
      assertThat(client!!.clientId).isEqualTo("testy")
      assertThat(client.clientName).isEqualTo("testy")
      assertThat(client.clientSecret).isEqualTo("encoded-client-secret")
      assertThat(client.authorizationGrantTypes).isEqualTo(GrantType.client_credentials.name)
      assertThat(client.scopes).containsOnly("read")
      assertFalse(clientConfigRepository.findById(client.clientId).isPresent)
      assertFalse(authorizationConsentRepository.findById(AuthorizationConsentId(client.id, client.clientId)).isPresent)

      verify(telemetryClient).trackEvent(
        "AuthorizationApiDetailsAdd",
        mapOf("username" to "AUTH_ADM", "clientId" to "testy", "grantType" to "client_credentials"),
        null,
      )

      clientRepository.delete(client)
    }

    @Test
    fun `omit mandatory fields gives bad request response`() {
      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "scopes" to listOf("read", "write"),
              "grantType" to "client_credentials",
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testy-mctest",
              "jiraNumber" to "HAAR-9999",
              "validDays" to 5,
              "accessTokenValiditySeconds" to 20,
            ),
          ),
        )
        .exchange()
        .expectStatus().isBadRequest
        .expectBody().jsonPath("errors").value(
          CoreMatchers.hasItems("clientId must not be blank"),
        )
    }
  }

  @Nested
  inner class EditClient {

    @Test
    fun `access unauthorized when no authority`() {
      webTestClient.put().uri("/base-clients/testy")
        .body(
          BodyInserters.fromValue(
            mapOf(
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testy-mctest",
              "jiraNumber" to "HAAR-9999",
              "validDays" to 5,
              "accessTokenValiditySeconds" to 20,
              "skipToAzure" to true,
              "resourceIds" to listOf("resource-id1", "resource-id2"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isUnauthorized
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.put().uri("/base-clients/testy")
        .headers(setAuthorisation(roles = listOf()))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testy-mctest",
              "jiraNumber" to "HAAR-9999",
              "validDays" to 5,
              "accessTokenValiditySeconds" to 20,
            ),
          ),
        )
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.put().uri("/base-clients/testy")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testy-mctest",
              "jiraNumber" to "HAAR-9999",
              "validDays" to 5,
              "accessTokenValiditySeconds" to 20,
            ),
          ),
        )
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `not found when client not found`() {
      webTestClient.put().uri("/base-clients/not-found")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testy-mctest",
              "jiraNumber" to "HAAR-9999",
              "validDays" to 5,
              "accessTokenValiditySeconds" to 20,
            ),
          ),
        )
        .exchange()
        .expectStatus().isNotFound
    }

    @Test
    fun `update complete client success`() {
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "test-test",
              "grantType" to "client_credentials",
              "clientName" to "testing testing",
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testy-mctest-1",
              "jiraNumber" to "HAAR-9999",
              "validDays" to 5,
              "accessTokenValiditySeconds" to 20,
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      webTestClient.put().uri("/base-clients/test-test")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "scopes" to listOf("read"),
              "authorities" to listOf("VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("82.135.209.29/32", "36.177.94.187/32"),
              "databaseUserName" to "testy-mctest-2",
              "jiraNumber" to "HAAR-8888",
              "validDays" to 3,
              "accessTokenValiditySeconds" to 10,
              "skipToAzure" to true,
              "resourceIds" to listOf("resource-id1", "resource-id2"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      val client = clientRepository.findClientByClientId("test-test")
      assertThat(client!!.scopes).contains("read")
      assertThat(client.tokenSettings.accessTokenTimeToLive).isEqualTo(Duration.ofSeconds(10))
      assertThat(registeredClientAdditionalInformation.getJiraNumber(client.clientSettings)).isEqualTo("HAAR-8888")
      assertThat(registeredClientAdditionalInformation.getDatabaseUserName(client.clientSettings)).isEqualTo("testy-mctest-2")
      assertThat(client.skipToAzure).isEqualTo(true)
      assertThat(client.resourceIds).isEqualTo(listOf("resource-id1", "resource-id2"))

      val clientConfig = clientConfigRepository.findById(client.clientId).get()
      assertThat(clientConfig.ips).contains("82.135.209.29/32", "36.177.94.187/32")
      assertThat(clientConfig.clientEndDate).isEqualTo(LocalDate.now().plusDays(2))
      val authorizationConsent =
        verifyAuthorities(client.id, client.clientId, "ROLE_VIEW_PRISONER_DATA", "ROLE_COMMUNITY")

      verify(telemetryClient).trackEvent(
        "AuthorizationApiCredentialsUpdate",
        mapOf("username" to "AUTH_ADM", "clientId" to "test-test"),
        null,
      )

      clientRepository.delete(client)
      clientConfigRepository.delete(clientConfig)
      authorizationConsentRepository.delete(authorizationConsent)
    }

    @Test
    fun `update client credentials client remove authorities`() {
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "test-test",
              "grantType" to "client_credentials",
              "clientName" to "testing testing",
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testy-mctest-1",
              "jiraNumber" to "HAAR-9999",
              "validDays" to 5,
              "accessTokenValiditySeconds" to 20,
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      var client = clientRepository.findClientByClientId("test-test")
      assertNotNull(client)
      verifyAuthorities(client!!.id, client.clientId, "ROLE_CURIOUS_API", "ROLE_VIEW_PRISONER_DATA", "ROLE_COMMUNITY")

      webTestClient.put().uri("/base-clients/test-test")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "scopes" to listOf("read"),
              "ips" to listOf("82.135.209.29/32", "36.177.94.187/32"),
              "databaseUserName" to "testy-mctest-2",
              "jiraNumber" to "HAAR-8888",
              "validDays" to 3,
              "accessTokenValiditySeconds" to 10,
              "skipToAzure" to true,
              "resourceIds" to listOf("resource-id1", "resource-id2"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      client = clientRepository.findClientByClientId("test-test")
      assertNotNull(client)
      val clientConfig = clientConfigRepository.findById(client!!.clientId).get()
      verifyAuthorizationConsentRecordNotPresent(client.id, client.clientId)

      clientConfigRepository.delete(clientConfig)
      clientRepository.delete(client)
    }

    @Test
    fun `update incomplete client success`() {
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "test-test",
              "grantType" to "client_credentials",
              "clientName" to "testing testing",
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      webTestClient.put().uri("/base-clients/test-test")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "scopes" to listOf("write"),
              "authorities" to listOf("VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("82.135.209.29/32", "36.177.94.187/32"),
              "databaseUserName" to "testy-mctest-2",
              "jiraNumber" to "HAAR-8888",
              "validDays" to 3,
              "accessTokenValiditySeconds" to 10,
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      val client = clientRepository.findClientByClientId("test-test")
      assertThat(client!!.scopes).contains("write")
      assertThat(client.tokenSettings.accessTokenTimeToLive).isEqualTo(Duration.ofSeconds(10))
      assertThat(registeredClientAdditionalInformation.getJiraNumber(client.clientSettings)).isEqualTo("HAAR-8888")
      assertThat(registeredClientAdditionalInformation.getDatabaseUserName(client.clientSettings)).isEqualTo("testy-mctest-2")

      val clientConfig = clientConfigRepository.findById(client.clientId).get()
      assertThat(clientConfig.ips).contains("82.135.209.29/32", "36.177.94.187/32")
      assertThat(clientConfig.clientEndDate).isEqualTo(LocalDate.now().plusDays(2))
      val authorizationConsent =
        verifyAuthorities(client.id, client.clientId, "ROLE_VIEW_PRISONER_DATA", "ROLE_COMMUNITY")

      verify(telemetryClient).trackEvent(
        "AuthorizationApiCredentialsUpdate",
        mapOf("username" to "AUTH_ADM", "clientId" to "test-test"),
        null,
      )

      clientRepository.delete(client)
      clientConfigRepository.delete(clientConfig)
      authorizationConsentRepository.delete(authorizationConsent)
    }
  }

  @Nested
  inner class ViewClient {

    @Test
    fun `access unauthorized when no authority`() {
      webTestClient.get().uri("/base-clients/testy")
        .exchange()
        .expectStatus().isUnauthorized
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.get().uri("/base-clients/testy")
        .headers(setAuthorisation(roles = listOf()))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.get().uri("/base-clients/testy")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `not found`() {
      webTestClient.get().uri("/base-clients/not-found")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isNotFound
    }

    @Test
    fun `should fail with not found`() {
      webTestClient.get().uri("/base-clients/test-client")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isNotFound
    }

    @Test
    fun `should find latest duplicate client id`() {
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      assertNull(clientRepository.findClientByClientId("test-client-id-1"))
      webTestClient.post().uri("/base-clients/test-client-id/clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("clientId").isEqualTo("test-client-id-1")

      // Get the latest client id (test-client-id-1)
      webTestClient.get().uri("/base-clients/test-client-id")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("clientId").isEqualTo("test-client-id-1")

      webTestClient.delete().uri("/base-clients/test-client-id/clients/test-client-id-1")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
    }

    @Test
    fun `view client without deployment details`() {
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
              "accessTokenValiditySeconds" to 20,
              "skipToAzure" to true,
              "resourceIds" to listOf("resource-id1", "resource-id2"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      webTestClient.get().uri("/base-clients/test-more-test")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
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
        .jsonPath("accessTokenValiditySeconds").isEqualTo(20)
        .jsonPath("grantType").isEqualTo("client_credentials")
        .jsonPath("deployment").isEmpty
        .jsonPath("skipToAzure").isEqualTo(true)
        .jsonPath("resourceIds[0]").isEqualTo("resource-id1")
        .jsonPath("resourceIds[1]").isEqualTo("resource-id2")

      val client = clientRepository.findClientByClientId("test-more-test")
      val clientConfig = clientConfigRepository.findById(client!!.clientId).get()
      val authorizationConsent = authorizationConsentRepository.findById(AuthorizationConsentId(client.id, client.clientId)).get()
      clientRepository.delete(client)
      clientConfigRepository.delete(clientConfig)
      authorizationConsentRepository.delete(authorizationConsent)

      verifyNoInteractions(authService)
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
              "accessTokenValiditySeconds" to 20,
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

      webTestClient.get().uri("/base-clients/test-more-test")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
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
        .jsonPath("accessTokenValiditySeconds").isEqualTo(20)
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
        .jsonPath("grantType").isEqualTo("client_credentials")
        .jsonPath("deployment.deploymentInfo").isEmpty

      val client = clientRepository.findClientByClientId("test-more-test")
      val clientConfig = clientConfigRepository.findById(client!!.clientId).get()
      val authorizationConsent = authorizationConsentRepository.findById(AuthorizationConsentId(client.id, client.clientId)).get()
      clientRepository.delete(client)
      clientConfigRepository.delete(clientConfig)
      authorizationConsentRepository.delete(authorizationConsent)
    }

    @Test
    fun `view authorization code client success`() {
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      val clientId = "test-auth-code"
      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to clientId,
              "scopes" to listOf("read", "write"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testy-more-mctest-1",
              "jiraNumber" to "HAAR-7777",
              "validDays" to 5,
              "accessTokenValiditySeconds" to 20,
              "jwtFields" to "-name",
              "mfaRememberMe" to true,
              "mfa" to "ALL",
              "grantType" to "authorization_code",
              "redirectUris" to "http://127.0.0.1:8089/authorized,https://oauth.pstmn.io/v1/callback",
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      val service = ServiceDetails(name = "Service name", description = "Service description", authorisedRoles = listOf("SERVICE_ROLE_1", "SERVICE_ROLE_2"), url = "http://url.com", enabled = false, contact = "email@email.com")

      whenever(authService.getService(any())).thenReturn(Optional.of(service))

      webTestClient.get().uri("/base-clients/$clientId")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("clientId").isEqualTo(clientId)
        .jsonPath("scopes[0]").isEqualTo("read")
        .jsonPath("scopes[1]").isEqualTo("write")
        .jsonPath("ips[0]").isEqualTo("81.134.202.29/32")
        .jsonPath("ips[1]").isEqualTo("35.176.93.186/32")
        .jsonPath("jiraNumber").isEqualTo("HAAR-7777")
        .jsonPath("validDays").isEqualTo(5)
        .jsonPath("accessTokenValiditySeconds").isEqualTo(20)
        .jsonPath("jwtFields").isEqualTo("-name")
        .jsonPath("mfaRememberMe").isEqualTo(true)
        .jsonPath("mfa").isEqualTo("ALL")
        .jsonPath("grantType").isEqualTo("authorization_code")
        .jsonPath("redirectUris[0]").isEqualTo("http://127.0.0.1:8089/authorized")
        .jsonPath("redirectUris[1]").isEqualTo("https://oauth.pstmn.io/v1/callback")
        .jsonPath("service.name").isEqualTo("Service name")
        .jsonPath("service.description").isEqualTo("Service description")
        .jsonPath("service.url").isEqualTo("http://url.com")
        .jsonPath("service.enabled").isEqualTo(false)
        .jsonPath("service.contact").isEqualTo("email@email.com")
        .jsonPath("service.authorisedRoles[0]").isEqualTo("SERVICE_ROLE_1")
        .jsonPath("service.authorisedRoles[1]").isEqualTo("SERVICE_ROLE_2")

      verify(authService).getService("test-auth-code")

      val client = clientRepository.findClientByClientId(clientId)
      val clientConfig = clientConfigRepository.findById(client!!.clientId).get()

      clientRepository.delete(client)
      clientConfigRepository.delete(clientConfig)
    }

    @Test
    fun `view authorization code client without service details`() {
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      val clientId = "test-auth-code"
      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to clientId,
              "scopes" to listOf("read", "write"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testy-more-mctest-1",
              "jiraNumber" to "HAAR-7777",
              "validDays" to 5,
              "accessTokenValiditySeconds" to 20,
              "jwtFields" to "-name",
              "mfaRememberMe" to true,
              "mfa" to "ALL",
              "grantType" to "authorization_code",
              "redirectUris" to "http://127.0.0.1:8089/authorized,https://oauth.pstmn.io/v1/callback",
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      whenever(authService.getService(any())).thenReturn(Optional.empty())

      webTestClient.get().uri("/base-clients/$clientId")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("clientId").isEqualTo(clientId)
        .jsonPath("service").isEmpty

      verify(authService).getService("test-auth-code")

      val client = clientRepository.findClientByClientId(clientId)
      val clientConfig = clientConfigRepository.findById(client!!.clientId).get()

      clientRepository.delete(client)
      clientConfigRepository.delete(clientConfig)
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

      webTestClient.get().uri("/base-clients/test-more-test")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("clientId").isEqualTo("test-more-test")
        .jsonPath("scopes[0]").isEqualTo("read")

      val client = clientRepository.findClientByClientId("test-more-test")
      assertNull(clientConfigRepository.findByIdOrNull(client!!.clientId))
      assertNull(authorizationConsentRepository.findByIdOrNull(AuthorizationConsentId(client.id, client.clientId)))
      clientRepository.delete(client)
    }
  }

  @Nested
  inner class AddUpdateClientDeployment {
    @Test
    fun `access unauthorized when no authority`() {
      webTestClient.put().uri("base-clients/testy/deployment")
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
        .expectStatus().isUnauthorized
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.put().uri("base-clients/testy/deployment")
        .headers(setAuthorisation(roles = listOf()))
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
    fun `access forbidden when wrong role`() {
      webTestClient.put().uri("base-clients/testy/deployment")
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

    @Test
    fun `client not found to upsert deployment information`() {
      webTestClient.put().uri("base-clients/testy/deployment")
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
    }

    @Test
    fun `add client deployment success`() {
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      webTestClient.put().uri("base-clients/test-complete-details-id/deployment")
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

      val clientDeployment = clientDeploymentRepository.findById("test-complete-details-id").get()
      assertThat(clientDeployment.baseClientId).isEqualTo("test-complete-details-id")
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
        "AuthorizationApiClientDeploymentDetailsUpsert",
        mapOf("username" to "AUTH_ADM", "baseClientId" to "test-complete-details-id"),
        null,
      )
    }

    @Test
    fun `Update client deployment success`() {
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      webTestClient.put().uri("base-clients/test-complete-details-id/deployment")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientType" to "PERSONAL",
              "team" to "testing team deployment update",
              "teamContact" to "testy lead update",
              "teamSlack" to "#testy_update",
              "hosting" to "CLOUDPLATFORM",
              "namespace" to "testy-testing-dev-update",
              "deployment" to "hmpps-testing-dev-update",
              "secretName" to "hmpps-testing-update",
              "clientIdKey" to "SYSTEM_CLIENT_ID-update",
              "secretKey" to "SYSTEM_CLIENT_SECRET-update",
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      val clientDeployment = clientDeploymentRepository.findById("test-complete-details-id").get()
      assertThat(clientDeployment.baseClientId).isEqualTo("test-complete-details-id")
      assertThat(clientDeployment.clientType).isEqualTo(ClientType.PERSONAL)
      assertThat(clientDeployment.team).isEqualTo("testing team deployment update")
      assertThat(clientDeployment.teamContact).isEqualTo("testy lead update")
      assertThat(clientDeployment.teamSlack).isEqualTo("#testy_update")
      assertThat(clientDeployment.hosting).isEqualTo(Hosting.CLOUDPLATFORM)
      assertThat(clientDeployment.namespace).isEqualTo("testy-testing-dev-update")
      assertThat(clientDeployment.deployment).isEqualTo("hmpps-testing-dev-update")
      assertThat(clientDeployment.secretName).isEqualTo("hmpps-testing-update")
      assertThat(clientDeployment.clientIdKey).isEqualTo("SYSTEM_CLIENT_ID-update")
      assertThat(clientDeployment.secretKey).isEqualTo("SYSTEM_CLIENT_SECRET-update")

      verify(telemetryClient).trackEvent(
        "AuthorizationApiClientDeploymentDetailsUpsert",
        mapOf("username" to "AUTH_ADM", "baseClientId" to "test-complete-details-id"),
        null,
      )
    }
  }

  private fun verifyAuthorities(id: String, clientId: String, vararg authorities: String): AuthorizationConsent {
    val authorizationConsent = authorizationConsentRepository.findById(AuthorizationConsentId(id, clientId)).get()
    assertThat(authorizationConsent.authorities).containsOnly(*authorities)
    return authorizationConsent
  }

  private fun verifyAuthorizationConsentRecordNotPresent(id: String, clientId: String) {
    val authorizationConsent = authorizationConsentRepository.findById(AuthorizationConsent.AuthorizationConsentId(id, clientId))
    assertFalse(authorizationConsent.isPresent)
  }
}
