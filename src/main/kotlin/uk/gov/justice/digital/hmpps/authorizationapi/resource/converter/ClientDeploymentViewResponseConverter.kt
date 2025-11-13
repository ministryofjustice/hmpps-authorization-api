package uk.gov.justice.digital.hmpps.authorizationapi.resource.converter

import org.springframework.core.convert.converter.Converter
import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationapi.resource.ClientDeploymentDetails
import uk.gov.justice.digital.hmpps.authorizationapi.resource.ClientDeploymentViewResponse

@Component
class ClientDeploymentViewResponseConverter : Converter<ClientDeploymentDetails, ClientDeploymentViewResponse> {

  override fun convert(source: ClientDeploymentDetails): ClientDeploymentViewResponse? = ClientDeploymentViewResponse(
    source,
  )
}
