package uk.gov.justice.digital.hmpps.authorizationserver.integration

import com.microsoft.applicationinsights.TelemetryClient
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.mockito.kotlin.verify
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.web.reactive.function.BodyInserters
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.AuthorizationConsent
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientType
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.Hosting
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.AuthorizationConsentRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientDeploymentRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientRepository
import uk.gov.justice.digital.hmpps.authorizationserver.service.RegisteredClientAdditionalInformation
import uk.gov.justice.digital.hmpps.authorizationserver.utils.OAuthClientSecret
import java.time.Duration
import java.time.LocalDate

class MigrationControllerIntTest : IntegrationTestBase() {

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

  @Autowired
  lateinit var jdbcRegisteredClientRepository: JdbcRegisteredClientRepository

  @Nested
  inner class MigrateClient {

    @Test
    fun `access forbidden when no authority`() {
      webTestClient.post().uri("/migrate-client")
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
              "clientName" to "test client",
              "grantType" to "client_credentials",
              "scopes" to listOf("read"),
              "authorities" to listOf("VIEW_PRISONER_DATA"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "clientSecret" to "clientSecret",
              "clientIdIssuedAt" to "2021-11-25T14:20:00Z",
            ),
          ),
        )
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.post().uri("/migrate-client")
        .headers(setAuthorisation(roles = listOf()))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
              "clientName" to "test client",
              "scopes" to listOf("read"),
              "authorities" to listOf("VIEW_PRISONER_DATA"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "clientSecret" to "clientSecret",
              "grantType" to "client_credentials",
              "clientIdIssuedAt" to "2021-11-25T14:20:00Z",
            ),
          ),
        )
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.post().uri("/migrate-client")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
              "clientName" to "test client",
              "grantType" to "client_credentials",
              "scopes" to listOf("read"),
              "authorities" to listOf("VIEW_PRISONER_DATA"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "clientSecret" to "clientSecret",
              "clientIdIssuedAt" to "2021-11-25T14:20:00Z",
            ),
          ),
        )
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `bad request when client already exists`() {
      assertNotNull(jdbcRegisteredClientRepository.findByClientId("test-client-id"))

      webTestClient.post().uri("/migrate-client")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "test-client-id",
              "clientName" to "test client",
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "clientSecret" to "clientSecret",
              "grantType" to "client_credentials",
              "clientIdIssuedAt" to "2021-11-25T14:20:00Z",
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

      webTestClient.post().uri("/migrate-client")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "ip-allow-a-client",
              "clientName" to "test client",
              "grantType" to "client_credentials",
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "clientSecret" to "clientSecret",
              "clientIdIssuedAt" to "2021-11-25T14:20:00Z",
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
    fun `migrate client success`() {
      assertNull(clientRepository.findClientByClientId("testz"))

      webTestClient.post().uri("/migrate-client")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testz",
              "grantType" to "client_credentials",
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "ROLE_COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testz-mctest",
              "jiraNumber" to "HAAR-9999",
              "validDays" to 5,
              "accessTokenValidityMinutes" to 20,
              "clientSecret" to "clientSecret",
              "clientIdIssuedAt" to "2021-11-25T14:20:00Z",
              "clientDeploymentDetails" to mapOf(
                "clientType" to "PERSONAL",
                "team" to "testing team",
                "teamContact" to "testz lead",
                "teamSlack" to "#testz",
                "hosting" to "CLOUDPLATFORM",
                "namespace" to "testz-testing-dev",
                "deployment" to "hmpps-testing-dev",
                "secretName" to "hmpps-testing",
                "clientIdKey" to "SYSTEM_CLIENT_ID",
                "secretKey" to "SYSTEM_CLIENT_SECRET",
              ),
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      val client = clientRepository.findClientByClientId("testz")

      assertNotNull(client)
      assertThat(client!!.clientId).isEqualTo("testz")
      assertThat(client.clientName).isEqualTo("testz")
      assertThat(client.clientSecret).isEqualTo("{bcrypt}clientSecret")
      assertThat(client.authorizationGrantTypes).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS.value)
      assertThat(client.scopes).contains("read", "write")
      assertThat(client.tokenSettings.accessTokenTimeToLive).isEqualTo(Duration.ofMinutes(20))
      assertThat(client.tokenSettings.settings[RegisteredClientAdditionalInformation.DATABASE_USER_NAME_KEY]).isEqualTo("testz-mctest")
      assertThat(client.tokenSettings.settings[RegisteredClientAdditionalInformation.JIRA_NUMBER_KEY]).isEqualTo("HAAR-9999")

      val clientConfig = clientConfigRepository.findById(client.clientId).get()
      assertThat(clientConfig.ips).contains("81.134.202.29/32", "35.176.93.186/32")
      assertThat(clientConfig.clientEndDate).isEqualTo(LocalDate.now().plusDays(4))
      val authorizationConsent =
        verifyAuthorities(client.id!!, client.clientId, "ROLE_CURIOUS_API", "ROLE_VIEW_PRISONER_DATA", "ROLE_COMMUNITY")

      val clientDeployment = clientDeploymentRepository.findById("testz").get()
      assertThat(clientDeployment.baseClientId).isEqualTo("testz")
      assertThat(clientDeployment.clientType).isEqualTo(ClientType.PERSONAL)
      assertThat(clientDeployment.team).isEqualTo("testing team")
      assertThat(clientDeployment.teamContact).isEqualTo("testz lead")
      assertThat(clientDeployment.teamSlack).isEqualTo("#testz")
      assertThat(clientDeployment.hosting).isEqualTo(Hosting.CLOUDPLATFORM)
      assertThat(clientDeployment.namespace).isEqualTo("testz-testing-dev")
      assertThat(clientDeployment.deployment).isEqualTo("hmpps-testing-dev")
      assertThat(clientDeployment.secretName).isEqualTo("hmpps-testing")
      assertThat(clientDeployment.clientIdKey).isEqualTo("SYSTEM_CLIENT_ID")
      assertThat(clientDeployment.secretKey).isEqualTo("SYSTEM_CLIENT_SECRET")

      verify(telemetryClient).trackEvent(
        "AuthorizationServerDetailsMigrate",
        mapOf("username" to "AUTH_ADM", "clientId" to "testz"),
        null,
      )

      clientRepository.delete(client)
      clientConfigRepository.delete(clientConfig)
      authorizationConsentRepository.delete(authorizationConsent)
    }

    @Test
    fun `migrate incomplete client`() {
      assertNull(clientRepository.findClientByClientId("testp"))

      webTestClient.post().uri("/migrate-client")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testp",
              "clientSecret" to "clientSecret",
              "grantType" to "client_credentials",
              "clientIdIssuedAt" to "2021-11-25T14:20:00Z",
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      val client = clientRepository.findClientByClientId("testp")

      assertNotNull(client)
      assertThat(client!!.clientId).isEqualTo("testp")
      assertThat(client.clientName).isEqualTo("testp")
      assertThat(client.clientSecret).isEqualTo("{bcrypt}clientSecret")
      assertThat(client.authorizationGrantTypes).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS.value)
      assertThat(client.scopes).containsOnly("read")
      assertFalse(clientConfigRepository.findById(client.clientId).isPresent)
      assertFalse(authorizationConsentRepository.findById(AuthorizationConsent.AuthorizationConsentId(client.id, client.clientId)).isPresent)

      verify(telemetryClient).trackEvent(
        "AuthorizationServerDetailsMigrate",
        mapOf("username" to "AUTH_ADM", "clientId" to "testp"),
        null,
      )

      clientRepository.delete(client)
    }
  }

  private fun verifyAuthorities(id: String, clientId: String, vararg authorities: String): AuthorizationConsent {
    val authorizationConsent = authorizationConsentRepository.findById(AuthorizationConsent.AuthorizationConsentId(id, clientId)).get()
    assertThat(authorizationConsent.authorities).containsOnly(*authorities)
    return authorizationConsent
  }
}