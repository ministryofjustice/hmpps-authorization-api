package uk.gov.justice.digital.hmpps.authorizationapi.data.repository

import org.springframework.data.repository.CrudRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.ClientDeployment

interface ClientDeploymentRepository : CrudRepository<ClientDeployment, String> {
  fun findClientDeploymentByBaseClientId(baseClientId: String): ClientDeployment?
  fun deleteByBaseClientId(baseClientId: String)
}
