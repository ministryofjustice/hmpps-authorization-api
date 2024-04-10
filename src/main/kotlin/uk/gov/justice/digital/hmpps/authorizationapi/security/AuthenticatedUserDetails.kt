package uk.gov.justice.digital.hmpps.authorizationapi.security

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.annotation.JsonProperty
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.User
import uk.gov.justice.digital.hmpps.authorizationapi.service.AuthSource

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
class AuthenticatedUserDetails(
  @JsonProperty("username")
  username: String,

  @JsonProperty("name")
  val name: String,

  @JsonProperty("authorities")
  authorities: Collection<GrantedAuthority>,

  @JsonProperty("authSource")
  val authSource: String = AuthSource.None.source,

  @JsonProperty("userId")
  val userId: String,

  @JsonProperty("jwtId")
  val jwtId: String,

  @JsonProperty("passedMfa")
  val passedMfa: Boolean = false,
) : User(username, "", authorities) {

  companion object {
    private const val serialVersionUID = 1L
  }
}
