package uk.gov.justice.digital.hmpps.authorizationserver.integration

import com.microsoft.applicationinsights.TelemetryClient
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.http.HttpStatus
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.web.reactive.function.BodyInserters
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.AuthorizationConsent
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.AuthorizationConsentRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientRepository
import uk.gov.justice.digital.hmpps.authorizationserver.service.RegisteredClientAdditionalInformation
import uk.gov.justice.digital.hmpps.authorizationserver.utils.OAuthClientSecret
import java.time.Duration
import java.time.LocalDate

class ClientCredentialsControllerIntTest : IntegrationTestBase() {

  @Autowired
  lateinit var jdbcRegisteredClientRepository: JdbcRegisteredClientRepository

  @Autowired
  lateinit var clientConfigRepository: ClientConfigRepository

  @Autowired
  lateinit var authorizationConsentRepository: AuthorizationConsentRepository

  @Autowired
  lateinit var clientRepository: ClientRepository

  @MockBean
  lateinit var oAuthClientSecretGenerator: OAuthClientSecret

  @MockBean
  private lateinit var telemetryClient: TelemetryClient

  @Nested
  inner class AddClient {

    @Test
    fun `access forbidden when no authority`() {
      webTestClient.post().uri("/clients/client-credentials/add")
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
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
    fun `access forbidden when no role`() {
      webTestClient.post().uri("/clients/client-credentials/add")
        .headers(setAuthorisation(roles = listOf()))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
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
      webTestClient.post().uri("/clients/client-credentials/add")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
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

      webTestClient.post().uri("/clients/client-credentials/add")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "test-client-id",
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
    fun `register client success`() {
      assertNull(clientRepository.findClientByClientId("testy"))
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      webTestClient.post().uri("/clients/client-credentials/add")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
              "clientName" to "test client",
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testy-mctest",
              "jiraNumber" to "HAAR-9999",
              "validDays" to 5,
              "accessTokenValidityMinutes" to 20,
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
      assertThat(client.clientName).isEqualTo("test client")
      assertThat(client.clientSecret).isEqualTo("encoded-client-secret")
      assertThat(client.authorizationGrantTypes).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS.value)
      assertThat(client.scopes).contains("read", "write")
      assertThat(client.tokenSettings.accessTokenTimeToLive).isEqualTo(Duration.ofMinutes(20))
      assertThat(client.tokenSettings.settings[RegisteredClientAdditionalInformation.DATABASE_USER_NAME_KEY]).isEqualTo("testy-mctest")
      assertThat(client.tokenSettings.settings[RegisteredClientAdditionalInformation.JIRA_NUMBER_KEY]).isEqualTo("HAAR-9999")

      val clientConfig = clientConfigRepository.findById(client.clientId).get()
      assertThat(clientConfig.ips).contains("81.134.202.29/32", "35.176.93.186/32")
      assertThat(clientConfig.clientEndDate).isEqualTo(LocalDate.now().plusDays(4))
      verifyAuthorities(client.id!!, client.clientId, "ROLE_CURIOUS_API", "ROLE_VIEW_PRISONER_DATA", "ROLE_COMMUNITY")

      verify(telemetryClient).trackEvent(
        "AuthorizationServerClientCredentialsDetailsAdd",
        mapOf("username" to "AUTH_ADM", "clientId" to "testy"),
        null,
      )

      clientRepository.delete(client)
    }
  }

  @Nested
  inner class EditClient {

    @Test
    fun `access forbidden when no authority`() {
      webTestClient.put().uri("/clients/client-credentials/testy/update")
        .body(
          BodyInserters.fromValue(
            mapOf(
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testy-mctest",
              "jiraNumber" to "HAAR-9999",
              "validDays" to 5,
              "accessTokenValidityMinutes" to 20,
            ),
          ),
        )
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.put().uri("/clients/client-credentials/testy/update")
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
              "accessTokenValidityMinutes" to 20,
            ),
          ),
        )
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.put().uri("/clients/client-credentials/testy/update")
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
              "accessTokenValidityMinutes" to 20,
            ),
          ),
        )
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `not found when client not found`() {
      webTestClient.put().uri("/clients/client-credentials/not-found/update")
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
              "accessTokenValidityMinutes" to 20,
            ),
          ),
        )
        .exchange()
        .expectStatus().isNotFound
    }

    @Test
    fun `not found when client config not found`() {
      webTestClient.put().uri("/clients/client-credentials/test-client-create-id/update")
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
              "accessTokenValidityMinutes" to 20,
            ),
          ),
        )
        .exchange()
        .expectStatus().isNotFound
    }

    @Test
    fun `update client success`() {
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      webTestClient.post().uri("/clients/client-credentials/add")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "test-test",
              "clientName" to "testing testing",
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testy-mctest-1",
              "jiraNumber" to "HAAR-9999",
              "validDays" to 5,
              "accessTokenValidityMinutes" to 20,
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      webTestClient.put().uri("/clients/client-credentials/test-test/update")
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
              "accessTokenValidityMinutes" to 10,
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      val client = clientRepository.findClientByClientId("test-test")
      assertThat(client!!.scopes).contains("read")
      assertThat(client.tokenSettings.accessTokenTimeToLive).isEqualTo(Duration.ofMinutes(10))
      assertThat(client.tokenSettings.settings[RegisteredClientAdditionalInformation.DATABASE_USER_NAME_KEY]).isEqualTo("testy-mctest-2")
      assertThat(client.tokenSettings.settings[RegisteredClientAdditionalInformation.JIRA_NUMBER_KEY]).isEqualTo("HAAR-8888")

      val clientConfig = clientConfigRepository.findById(client.clientId).get()
      assertThat(clientConfig.ips).contains("82.135.209.29/32", "36.177.94.187/32")
      assertThat(clientConfig.clientEndDate).isEqualTo(LocalDate.now().plusDays(2))
      verifyAuthorities(client.id!!, client.clientId, "ROLE_VIEW_PRISONER_DATA", "ROLE_COMMUNITY")

      verify(telemetryClient).trackEvent(
        "AuthorizationServerClientCredentialsUpdate",
        mapOf("username" to "AUTH_ADM", "clientId" to "test-test"),
        null,
      )

      clientRepository.delete(client)
    }
  }

  @Nested
  inner class DuplicateClient {

    @Test
    fun `access forbidden when no authority`() {
      webTestClient.post().uri("/clients/client-credentials/test-client-id/duplicate")
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.post().uri("/clients/client-credentials/test-client-id/duplicate")
        .headers(setAuthorisation(roles = listOf()))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.post().uri("/clients/client-credentials/test-client-id/duplicate")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `not found when no clients exist for base client id`() {
      webTestClient.post().uri("/clients/client-credentials/test-client-x-id/duplicate")
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

      webTestClient.post().uri("/clients/client-credentials/test-client-id/duplicate")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk

      webTestClient.post().uri("/clients/client-credentials/test-client-id/duplicate")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk

      val duplicatedClient = clientRepository.findClientByClientId("test-client-id-1")
      val duplicatedClient2 = clientRepository.findClientByClientId("test-client-id-2")

      webTestClient.post().uri("/clients/client-credentials/test-client-id/duplicate")
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

      webTestClient.post().uri("/clients/client-credentials/test-client-id/duplicate")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("clientId").isEqualTo("test-client-id-1")
        .jsonPath("clientSecret").isEqualTo("external-client-secret")

      val originalClient = clientRepository.findClientByClientId("test-client-id")
      val duplicatedClient = clientRepository.findClientByClientId("test-client-id-1")
      assertThat(duplicatedClient!!.clientName).isEqualTo(originalClient!!.clientName)
      assertThat(duplicatedClient.scopes).isEqualTo(originalClient.scopes)
      assertThat(duplicatedClient.authorizationGrantTypes).isEqualTo(originalClient.authorizationGrantTypes)
      assertThat(duplicatedClient.clientAuthenticationMethods).isEqualTo(originalClient.clientAuthenticationMethods)
      assertThat(duplicatedClient.clientSettings).isEqualTo(originalClient.clientSettings)
      assertThat(duplicatedClient.tokenSettings).isEqualTo(originalClient.tokenSettings)

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
      webTestClient.get().uri("/clients/client-credentials/testy/view")
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.get().uri("/clients/client-credentials/testy/view")
        .headers(setAuthorisation(roles = listOf()))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.get().uri("/clients/client-credentials/testy/view")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `not found`() {
      webTestClient.get().uri("/clients/client-credentials/not-found/view")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isNotFound
    }

    @Test
    fun `view client success`() {
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      webTestClient.post().uri("/clients/client-credentials/add")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "test-more-test",
              "clientName" to "test more testing",
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

      webTestClient.get().uri("/clients/client-credentials/test-more-test/view")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("clientId").isEqualTo("test-more-test")
        .jsonPath("clientName").isEqualTo("test more testing")
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

      val client = clientRepository.findClientByClientId("test-more-test")
      clientRepository.delete(client)
    }
  }

  private fun verifyAuthorities(id: String, clientId: String, vararg authorities: String) {
    val authorizationConsent = authorizationConsentRepository.findById(AuthorizationConsent.AuthorizationConsentId(id, clientId)).get()
    assertThat(authorizationConsent.authorities).containsOnly(*authorities)
  }
}
