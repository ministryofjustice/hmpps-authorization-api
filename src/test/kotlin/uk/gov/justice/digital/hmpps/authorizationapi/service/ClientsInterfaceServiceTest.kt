package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.springframework.core.convert.ConversionService
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import uk.gov.justice.digital.hmpps.authorizationapi.adapter.AuthService
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.AuthorizationConsent
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.Client
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.ClientConfig
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.AuthorizationConsentRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientDeploymentRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientRepository
import uk.gov.justice.digital.hmpps.authorizationapi.resource.ClientUpdateRequest
import uk.gov.justice.digital.hmpps.authorizationapi.utils.OAuthClientSecret
import java.time.LocalDateTime
import java.util.*

class ClientsInterfaceServiceTest {

  private val clientRepository: ClientRepository = mock()
  private val clientConfigRepository: ClientConfigRepository = mock()
  private val authorizationConsentRepository: AuthorizationConsentRepository = mock()
  private val clientIdService: ClientIdService = mock()
  private val clientDeploymentRepository: ClientDeploymentRepository = mock()
  private val oAuthClientSecret: OAuthClientSecret = mock()
  private val registeredClientAdditionalInformation: RegisteredClientAdditionalInformation = mock()
  private val conversionService: ConversionService = mock()
  private val authService: AuthService = mock()
  private val clientsInterfaceService: ClientsInterfaceService = ClientsInterfaceService(
    clientRepository,
    clientConfigRepository,
    authorizationConsentRepository,
    clientIdService,
    clientDeploymentRepository,
    oAuthClientSecret,
    registeredClientAdditionalInformation,
    conversionService,
    authService,
  )

  @BeforeEach
  fun setup() {
    whenever(registeredClientAdditionalInformation.buildTokenSettings(any())).thenReturn(TokenSettings.builder().build())
    whenever(registeredClientAdditionalInformation.buildClientSettings(any(), any(), any())).thenReturn(ClientSettings.builder().build())
    whenever(clientIdService.toBase(CLIENT_ID)).thenReturn(CLIENT_ID)
  }

  @Nested
  inner class EditClient {
    @Test
    fun `creates and saves a new authorization consent if the updated client has authorities`() {
      val existingClient = getTestClient()
      val newAuthorities = listOf("ROLE_TEST")
      val updatedClient = getUpdatedClient(newAuthorities)
      val expectedAuthorizationConsent = AuthorizationConsent(existingClient.id, existingClient.clientId, newAuthorities)
      whenever(clientIdService.findByBaseClientId(CLIENT_ID)).thenReturn(listOf(existingClient))
      whenever(clientConfigRepository.findById(CLIENT_ID)).thenReturn(Optional.of(ClientConfig(CLIENT_ID)))
      whenever(authorizationConsentRepository.findById(AuthorizationConsent.AuthorizationConsentId(existingClient.id, existingClient.clientId))).thenReturn(Optional.empty())

      clientsInterfaceService.editClient(CLIENT_ID, updatedClient)

      verify(authorizationConsentRepository).save(expectedAuthorizationConsent)
    }

    @Test
    fun `updates the authorities on the existing authorization consent if the updated client has authorities`() {
      val existingClient = getTestClient()
      val existingAuthorities = listOf("ROLE_TEST", "ROLE_ADMIN_TEST")
      val newAuthorities = listOf("ROLE_TEST")
      val updatedClient = getUpdatedClient(newAuthorities)
      val expectedAuthorizationConsent = AuthorizationConsent(existingClient.id, existingClient.clientId, newAuthorities)
      whenever(clientIdService.findByBaseClientId(CLIENT_ID)).thenReturn(listOf(existingClient))
      whenever(clientIdService.toBase(CLIENT_ID)).thenReturn(CLIENT_ID)
      whenever(clientConfigRepository.findById(CLIENT_ID)).thenReturn(Optional.of(ClientConfig(CLIENT_ID)))
      whenever(authorizationConsentRepository.findById(AuthorizationConsent.AuthorizationConsentId(existingClient.id, existingClient.clientId))).thenReturn(
        Optional.of(
          AuthorizationConsent(
            existingClient.id,
            existingClient.clientId,
            existingAuthorities,
          ),
        ),
      )

      clientsInterfaceService.editClient(CLIENT_ID, updatedClient)

      verify(authorizationConsentRepository).save(expectedAuthorizationConsent)
    }

    @Test
    fun `deletes the existing authorization consent if the updated client has no authorities`() {
      val existingClient = getTestClient()
      val existingAuthorities = listOf("ROLE_TEST", "ROLE_ADMIN_TEST")
      val newAuthorities = emptyList<String>()
      val updatedClient = getUpdatedClient(newAuthorities)
      whenever(clientIdService.findByBaseClientId(CLIENT_ID)).thenReturn(listOf(existingClient))
      whenever(clientIdService.toBase(CLIENT_ID)).thenReturn(CLIENT_ID)
      whenever(clientConfigRepository.findById(CLIENT_ID)).thenReturn(Optional.of(ClientConfig(CLIENT_ID)))
      val existingAuthorizationConsent = AuthorizationConsent(
        existingClient.id,
        existingClient.clientId,
        existingAuthorities,
      )
      whenever(authorizationConsentRepository.findById(AuthorizationConsent.AuthorizationConsentId(existingClient.id, existingClient.clientId))).thenReturn(
        Optional.of(
          existingAuthorizationConsent,
        ),
      )

      clientsInterfaceService.editClient(CLIENT_ID, updatedClient)

      verify(authorizationConsentRepository).delete(existingAuthorizationConsent)
      verify(authorizationConsentRepository, never()).save(any())
    }

    @Test
    fun `does not create and save an authorization consent the updated client has no authorities`() {
      val existingClient = getTestClient()
      val newAuthorities = emptyList<String>()
      val updatedClient = getUpdatedClient(newAuthorities)
      whenever(clientIdService.findByBaseClientId(CLIENT_ID)).thenReturn(listOf(existingClient))
      whenever(clientIdService.toBase(CLIENT_ID)).thenReturn(CLIENT_ID)
      whenever(clientConfigRepository.findById(CLIENT_ID)).thenReturn(Optional.of(ClientConfig(CLIENT_ID)))
      whenever(authorizationConsentRepository.findById(AuthorizationConsent.AuthorizationConsentId(existingClient.id, existingClient.clientId))).thenReturn(Optional.empty())

      clientsInterfaceService.editClient(CLIENT_ID, updatedClient)

      verify(authorizationConsentRepository, never()).save(any())
    }
  }

  companion object {
    const val CLIENT_ID = "test-client-id"

    private fun getTestClient(clientId: String = CLIENT_ID) = Client(
      id = "1234567890",
      clientId = clientId,
      clientIdIssuedAt = LocalDateTime.now(),
      clientSecret = "thisIsASecret",
      clientSecretExpiresAt = null,
      clientName = "uber-client",
      clientAuthenticationMethods = "",
      authorizationGrantTypes = "client_credentials",
      redirectUris = "http://localhost:8080",
      postLogoutRedirectUris = "https://localhost:8080",
      scopes = listOf("read", "write"),
      clientSettings = ClientSettings.builder().build(),
      tokenSettings = TokenSettings.builder().build(),
      mfaRememberMe = false,
      mfa = null,
      skipToAzure = false,
      resourceIds = emptyList(),
    )
    private fun getUpdatedClient(authorities: List<String>): ClientUpdateRequest = ClientUpdateRequest(
      emptyList(), authorities, emptyList(), "JIRA", "USER", null, 3600L, "JWT", false,
      null, null, null, null,
    )
  }
}
