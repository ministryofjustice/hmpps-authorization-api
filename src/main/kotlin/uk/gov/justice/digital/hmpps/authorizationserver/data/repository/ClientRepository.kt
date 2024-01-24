package uk.gov.justice.digital.hmpps.authorizationserver.data.repository

import org.springframework.data.repository.CrudRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.Client

interface ClientRepository : CrudRepository<Client, String> {
  fun findClientByClientId(clientId: String): Client?

  fun findByClientIdStartsWithOrderByClientId(clientId: String): List<Client>

  fun deleteByClientId(clientId: String)
}
