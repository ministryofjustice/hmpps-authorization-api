package uk.gov.justice.digital.hmpps.authorizationapi.data.repository

import org.springframework.data.repository.CrudRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.ClientConfig

interface ClientConfigRepository : CrudRepository<ClientConfig, String> {
  fun deleteByBaseClientId(baseClientId: String)
}
