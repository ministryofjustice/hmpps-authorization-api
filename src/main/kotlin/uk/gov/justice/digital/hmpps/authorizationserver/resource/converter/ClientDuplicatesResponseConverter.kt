package uk.gov.justice.digital.hmpps.authorizationserver.resource.converter

import org.springframework.core.convert.converter.Converter
import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.Client
import uk.gov.justice.digital.hmpps.authorizationserver.resource.ClientDateSummary
import uk.gov.justice.digital.hmpps.authorizationserver.resource.ClientDuplicatesResponse
import uk.gov.justice.digital.hmpps.authorizationserver.resource.GrantType

@Component
class ClientDuplicatesResponseConverter : Converter<List<Client>, ClientDuplicatesResponse> {
  override fun convert(source: List<Client>): ClientDuplicatesResponse {
    val clientDateSummaries = source.map { client ->
      ClientDateSummary(
        clientId = client.clientId,
        created = client.clientIdIssuedAt,
        lastAccessed = client.getLastAccessedDate(),
      )
    }

    return ClientDuplicatesResponse(clientDateSummaries, GrantType.valueOf(source[0].authorizationGrantTypes.uppercase()))
  }
}
