package uk.gov.justice.digital.hmpps.authorizationserver.data.repository

import org.springframework.data.repository.CrudRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.Authorization
import java.time.LocalDateTime

interface AuthorizationRepository : CrudRepository<Authorization, String> {
  fun deleteByAccessTokenExpiresAtBefore(createDate: LocalDateTime)
}
