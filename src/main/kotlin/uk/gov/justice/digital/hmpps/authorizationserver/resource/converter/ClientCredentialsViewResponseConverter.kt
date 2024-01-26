package uk.gov.justice.digital.hmpps.authorizationserver.resource.converter

import org.springframework.core.convert.converter.Converter
import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationserver.resource.ClientViewResponse
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientComposite

@Component
class ClientCredentialsViewResponseConverter : Converter<ClientComposite, ClientViewResponse> {

  override fun convert(source: ClientComposite): ClientViewResponse? {
    with(source) {
      return ClientViewResponse(
        latestClient.clientId,
        latestClient.scopes,
        authorizationConsent?.authorities,
        clientConfig?.ips,
        latestClient.getJiraNumber(),
        latestClient.getDatabaseUserName(),
        clientConfig?.validDays,
        latestClient.tokenSettings.accessTokenTimeToLive.toMinutes(),
        deployment,
        latestClient.jwtFields,
        latestClient.mfaRememberMe,
        latestClient.mfa,
        latestClient.getRegisteredRedirectUriWithNewlines(),
      )
    }
  }
}
