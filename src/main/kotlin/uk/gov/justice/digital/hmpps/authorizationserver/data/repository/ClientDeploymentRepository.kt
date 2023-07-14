package uk.gov.justice.digital.hmpps.authorizationserver.data.repository

import org.springframework.data.repository.CrudRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientDeployment

interface ClientDeploymentRepository : CrudRepository<ClientDeployment, String> {
  fun findClientDeploymentByBaseClientId(baseClientId: String): ClientDeployment?
}
