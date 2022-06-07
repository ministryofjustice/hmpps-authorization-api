package uk.gov.justice.digital.hmpps.hmppsauthorizationserver.model

import org.springframework.data.repository.CrudRepository
import org.springframework.stereotype.Repository

@Repository
interface RegisteredUserRepository : CrudRepository<RegisteredUser, Long> {
  fun findByUserName(userName: String) : RegisteredUser?
}