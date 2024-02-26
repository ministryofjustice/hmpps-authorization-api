package uk.gov.justice.digital.hmpps.authorizationserver.resource.converter

import org.springframework.core.convert.converter.Converter
import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.Client
import uk.gov.justice.digital.hmpps.authorizationserver.resource.ClientExistsResponse

@Component
class ClientExistsResponseConverter : Converter<Client, ClientExistsResponse> {
  override fun convert(source: Client): ClientExistsResponse? {
    with(source) {
      return ClientExistsResponse(
        clientId,
        tokenSettings.accessTokenTimeToLive.toSeconds(),
      )
    }
  }
}
