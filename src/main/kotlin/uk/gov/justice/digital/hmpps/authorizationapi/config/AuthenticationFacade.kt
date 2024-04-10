package uk.gov.justice.digital.hmpps.authorizationapi.config

import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Component

@Component
class AuthenticationFacade {
  val authentication: Authentication
    get() = SecurityContextHolder.getContext().authentication
  val currentUsername: String?
    get() {
      val username: String?
      val userPrincipal = userPrincipal
      username = when (userPrincipal) {
        is String -> {
          userPrincipal
        }
        is UserDetails -> {
          userPrincipal.username
        }
        is Map<*, *> -> {
          userPrincipal["username"] as String?
        }
        else -> {
          null
        }
      }
      return username
    }

  private val userPrincipal: Any?
    get() {
      return authentication.principal
    }
}
