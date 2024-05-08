package uk.gov.justice.digital.hmpps.authorizationapi.resource.converter

import org.springframework.core.convert.converter.Converter
import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationapi.resource.ClientViewResponse
import uk.gov.justice.digital.hmpps.authorizationapi.resource.GrantType
import uk.gov.justice.digital.hmpps.authorizationapi.service.ClientComposite
import uk.gov.justice.digital.hmpps.authorizationapi.service.RegisteredClientAdditionalInformation

@Component
class ClientCredentialsViewResponseConverter : Converter<ClientComposite, ClientViewResponse> {

  override fun convert(source: ClientComposite): ClientViewResponse? {
    with(source) {
      return ClientViewResponse(
        latestClient.clientId,
        latestClient.scopes,
        authorizationConsent?.authorities,
        clientConfig?.ips,
        latestClient.clientSettings.getSetting(RegisteredClientAdditionalInformation.JIRA_NUMBER_KEY),
        latestClient.clientSettings.getSetting(RegisteredClientAdditionalInformation.DATABASE_USER_NAME_KEY),
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
