package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.whenever
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.Client
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.ClientConfig
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.AuthorizationConsentRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientRepository
import uk.gov.justice.digital.hmpps.authorizationapi.resource.ClientDetailsResponse
import java.time.Instant
import java.time.LocalDate

@ExtendWith(MockitoExtension::class)
class ClientDataServiceTest {

  private lateinit var service: ClientDataService

  @Mock
  private lateinit var clientRepository: ClientRepository

  @Mock
  private lateinit var clientConfigRepository: ClientConfigRepository

  @Mock
  private lateinit var authorizationConsentRepository: AuthorizationConsentRepository

  @Mock
  private lateinit var clientIdService: ClientIdService

  @Mock
  private lateinit var clientConfig: ClientConfig

  private lateinit var testClient: Client

  @Nested
  inner class ClientExpiryTest {
    @BeforeEach
    fun setup() {
      service = ClientDataService(
        clientRepository,
        clientConfigRepository,
        authorizationConsentRepository,
        clientIdService,
      )

      testClient = getTestClient()

      whenever(clientRepository.findAll()).thenReturn(listOf(testClient))
      whenever(clientConfigRepository.findAll()).thenReturn(listOf(clientConfig))
      whenever(clientIdService.toBase(CLIENT_ID)).thenReturn(CLIENT_ID)
      whenever(clientConfig.baseClientId).thenReturn(CLIENT_ID)
      whenever(clientConfig.clientEndDate).thenReturn(null)
      whenever(clientConfig.ips).thenReturn(listOf("127.0.0.1"))
      whenever(clientConfig.baseClientId).thenReturn(CLIENT_ID)
    }

    @Test
    fun `expired is false when clientConfig clientEndDate is null`() {
      whenever(clientConfig.clientEndDate).thenReturn(null)

      val actual = service.fetchClientDetails()

      assertClientDetailsResponse(actual, false)
    }

    @Test
    fun `expired false when clientConfig clientEndDate is in the future`() {
      val expiryDate = LocalDate.now().plusMonths(6)
      whenever(clientConfig.clientEndDate).thenReturn(expiryDate)

      val actual = service.fetchClientDetails()

      assertClientDetailsResponse(actual, false)
    }

    @Test
    fun `expired true when clientConfig clientEndDate is in the past`() {
      val expiryDate = LocalDate.now().minusMonths(6)
      whenever(clientConfig.clientEndDate).thenReturn(expiryDate)

      val actual = service.fetchClientDetails()

      assertClientDetailsResponse(actual, true)
    }

    private fun assertClientDetailsResponse(actual: List<ClientDetailsResponse>, expectedExpired: Boolean) {
      assertThat(actual).isNotNull
      assertThat(actual).hasSize(1)
      assertThat(actual[0].clientId).isEqualTo(CLIENT_ID)
      assertThat(actual[0].scopes).isEqualTo(listOf("read", "write"))
      assertThat(actual[0].mfaRememberMe).isFalse()
      assertThat(actual[0].mfa).isNull()
      assertThat(actual[0].authorities).isNull()
      assertThat(actual[0].skipToAzure).isFalse()
      assertThat(actual[0].ips).containsExactly("127.0.0.1")
      assertThat(actual[0].expired).isEqualTo(expectedExpired)
      assertThat(actual[0].redirectUris).isEqualTo(listOf("http://localhost:8080"))
    }

    private fun getTestClient() = Client(
      id = "1234567890",
      clientId = CLIENT_ID,
      clientIdIssuedAt = Instant.now().minusSeconds(TWENTY_FOUR_HOURS_IN_SECONDS),
      clientSecret = "thisIsASecret",
      clientSecretExpiresAt = null,
      clientName = "uber-client",
      clientAuthenticationMethods = "",
      authorizationGrantTypes = "",
      redirectUris = "http://localhost:8080",
      postLogoutRedirectUris = "https://localhost:8080",
      scopes = listOf("read", "write"),
      clientSettings = ClientSettings.builder().build(),
      tokenSettings = TokenSettings.builder().build(),
      latestClientAuthorization = null,
      mfaRememberMe = false,
      mfa = null,
      skipToAzure = false,
      resourceIds = emptyList(),
    )
  }

  companion object {
    const val TWENTY_FOUR_HOURS_IN_SECONDS: Long = 86400
    const val CLIENT_ID = "test-client-id"
  }
}
