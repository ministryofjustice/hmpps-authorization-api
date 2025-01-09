package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Service
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.AuthorizationConsent
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.Client
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.ClientConfig
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.AuthorizationConsentRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientRepository
import uk.gov.justice.digital.hmpps.authorizationapi.resource.ClientDetailsResponse
import java.time.LocalDate

@Service
class ClientDataService(
  private val clientRepository: ClientRepository,
  private val clientConfigRepository: ClientConfigRepository,
  private val authorizationConsentRepository: AuthorizationConsentRepository,
  private val clientIdService: ClientIdService,
) {

  fun fetchClientDetails(): List<ClientDetailsResponse> {
    val allClients = clientRepository.findAll()
    val allClientConfigsMap = clientConfigRepository.findAll().associateBy { it.baseClientId }
    return allClients.map { client -> mapToClientDetails(client, allClientConfigsMap) }
  }

  private fun mapToClientDetails(client: Client, clientConfigsMap: Map<String, ClientConfig>) =
    with(client) {
      ClientDetailsResponse(
        clientId = clientId,
        scopes = scopes,
        mfaRememberMe = mfaRememberMe,
        mfa = mfa,
        authorities = retrieveAuthorizationConsent(client)?.authorities,
        skipToAzure = skipToAzure,
        ips = clientConfigsMap[clientIdService.toBase(clientId)]?.ips,
        expired = isExpired(clientId, clientConfigsMap),
        redirectUris = getRegisteredRedirectUriWithNewlines()?.toList(),
      )
    }

  private fun retrieveAuthorizationConsent(client: Client) =
    authorizationConsentRepository.findByIdOrNull(
      AuthorizationConsent.AuthorizationConsentId(
        client.id,
        client.clientId,
      ),
    )

  private fun isExpired(clientId: String, clientConfigsMap: Map<String, ClientConfig>) =
    clientConfigsMap[clientIdService.toBase(clientId)]?.clientEndDate?.isBefore(LocalDate.now()) ?: false
}
