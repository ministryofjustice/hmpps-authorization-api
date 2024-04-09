package uk.gov.justice.digital.hmpps.authorizationapi.data.repository

import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.CrudRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.Authorization

interface AuthorizationRepository : CrudRepository<Authorization, String> {

  @Modifying
  @Query("delete from Authorization where accessTokenIssuedAt not in(select max(accessTokenIssuedAt) from Authorization group by principalName)")
  fun deleteAllButLatestClientCredentialsAccessToken()

  @Modifying
  @Query("delete from Authorization where authorizationCodeIssuedAt not in(select max(authorizationCodeIssuedAt) from Authorization group by principalName)")
  fun deleteAllButLatestAuthorizationCodeAccessToken()
}
