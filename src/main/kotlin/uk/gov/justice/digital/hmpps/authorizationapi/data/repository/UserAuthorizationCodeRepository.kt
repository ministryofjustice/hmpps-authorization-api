package uk.gov.justice.digital.hmpps.authorizationapi.data.repository

import org.springframework.data.repository.CrudRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.UserAuthorizationCode

interface UserAuthorizationCodeRepository : CrudRepository<UserAuthorizationCode, String>
