package uk.gov.justice.digital.hmpps.authorizationserver.resource.converter

import org.springframework.core.convert.converter.Converter
import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationserver.resource.ClientViewResponse
import uk.gov.justice.digital.hmpps.authorizationserver.resource.GrantType
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
        latestClient.jira,
        latestClient.databaseUsername,
        clientConfig?.validDays,
        latestClient.tokenSettings.accessTokenTimeToLive.seconds,
        deployment,
        latestClient.jwtFields,
        latestClient.mfaRememberMe,
        latestClient.mfa,
        latestClient.getRegisteredRedirectUriWithNewlines(),
        GrantType.valueOf(latestClient.authorizationGrantTypes),
        service,
        latestClient.skipToAzureField,
        latestClient.resourceIds,
      )
    }
  }
}
