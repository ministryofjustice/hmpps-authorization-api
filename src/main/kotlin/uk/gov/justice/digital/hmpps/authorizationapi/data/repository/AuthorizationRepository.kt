package uk.gov.justice.digital.hmpps.authorizationapi.data.repository

import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.CrudRepository
import org.springframework.data.repository.query.Param
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.Authorization

interface AuthorizationRepository : CrudRepository<Authorization, String> {
  fun findByState(token: String): Authorization?
  fun findByAuthorizationCodeValue(authorizationCodeValue: String): Authorization?
  fun findByAccessTokenValue(accessTokenValue: String): Authorization?

  @Query(
    "select a from Authorization a where a.state = :token" +
      " or a.authorizationCodeValue = :token" +
      " or a.accessTokenValue = :token",
  )
  fun findByStateOrAuthorizationCodeValueOrAccessTokenValue(@Param("token") token: String): Authorization?
}
