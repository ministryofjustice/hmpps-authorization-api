package uk.gov.justice.digital.hmpps.authorizationserver.resource.converter

import org.springframework.core.convert.converter.Converter
import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationserver.resource.ClientCredentialsViewResponse
import uk.gov.justice.digital.hmpps.authorizationserver.service.AllClientDetails

@Component
class ClientCredentialsViewResponseConverter : Converter<AllClientDetails, ClientCredentialsViewResponse> {

  override fun convert(source: AllClientDetails): ClientCredentialsViewResponse? {
    with(source) {
      return ClientCredentialsViewResponse(
        latestClient.clientId,
        latestClient.clientName,
        latestClient.scopes,
        authorizationConsent.authorities,
        clientConfig.ips,
        latestClient.getJiraNumber(),
        latestClient.getDatabaseUserName(),
        clientConfig.validDays,
        latestClient.tokenSettings.accessTokenTimeToLive.toMinutes(),
      )
    }
  }
}
