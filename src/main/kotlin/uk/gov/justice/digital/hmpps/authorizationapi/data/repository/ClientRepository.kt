package uk.gov.justice.digital.hmpps.authorizationapi.data.repository

import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.CrudRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.Client

interface ClientRepository : CrudRepository<Client, String> {
  fun findClientByClientId(clientId: String): Client?

  fun findByClientIdStartsWithOrderByClientId(clientId: String): List<Client>

  @Modifying
  @Query("delete from Client c where c.clientId=:clientId")
  fun deleteByClientId(clientId: String)
}
