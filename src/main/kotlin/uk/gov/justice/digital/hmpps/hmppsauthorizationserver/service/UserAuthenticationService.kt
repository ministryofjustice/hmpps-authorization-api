package uk.gov.justice.digital.hmpps.hmppsauthorizationserver.service

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Service
import uk.gov.justice.digital.hmpps.hmppsauthorizationserver.model.RegisteredUserRepository

@Service
class UserAuthenticationService(private val userRepository: RegisteredUserRepository) : UserDetailsService {

  override fun loadUserByUsername(username: String): UserDetails {
    val registeredUser = userRepository.findByUserName(username)

    // TODO raise UsernameNotFoundException if registeredUser is null
    val authorities = listOf<GrantedAuthority>(SimpleGrantedAuthority(registeredUser?.role))
    return User(registeredUser?.id.toString(), registeredUser?.password, authorities)
  }
}