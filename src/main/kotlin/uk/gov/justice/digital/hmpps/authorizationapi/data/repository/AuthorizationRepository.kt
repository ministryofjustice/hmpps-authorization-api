package uk.gov.justice.digital.hmpps.authorizationapi.data.repository

import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.CrudRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.Authorization

interface AuthorizationRepository : CrudRepository<Authorization, String> {

  @Modifying
  @Query("delete from Authorization where accessTokenIssuedAt not in(select max(accessTokenIssuedAt) from Authorization group by principalName)")
  fun deleteAllButLatestAccessToken(): Int

  @Modifying
  @Query("delete from Authorization where accessTokenIssuedAt is null and  authorizationCodeExpiresAt < cast(current_timestamp as instant)")
  fun deleteAllAuthorizationCodeRecordsWithoutAccessTokens(): Int

  @Modifying
  @Query(
    value = "delete from oauth2_user_authorization_code where current_timestamp + INTERVAL '20 minutes' > authorization_code_issued_at",
    nativeQuery = true,
  )
  fun deleteRecordsOlderThan20Minutes(): Int
}
