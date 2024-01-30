package uk.gov.justice.digital.hmpps.authorizationserver.security

import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import java.time.Duration
import java.util.Optional
import java.util.stream.Stream

open class CookieHelper(protected val name: String, private val expiryTime: Duration) {

  open fun addCookieToResponse(request: HttpServletRequest, response: HttpServletResponse, value: String?) {
    // Add a session cookie
    val sessionCookie = Cookie(name, value)

    // path has to match exactly the path defined in spring's CookieClearingLogoutHandler
    sessionCookie.path = request.contextPath
    sessionCookie.domain = "auth.com" // TODO domain will need to come from configuration

    // expiry time of 0 means that cookie never expires
    if (expiryTime.toSeconds() != 0L) {
      sessionCookie.maxAge = Math.toIntExact(expiryTime.toSeconds())
    }
    sessionCookie.isHttpOnly = true
    sessionCookie.secure = request.isSecure
    response.addCookie(sessionCookie)
  }

  open fun readValueFromCookie(request: HttpServletRequest): Optional<String> {
    return Stream.of(*Optional.ofNullable(request.cookies).orElse(arrayOfNulls(0)))
      .filter { c: Cookie -> name == c.name }
      .map { it.value }
      .findFirst()
  }
}
