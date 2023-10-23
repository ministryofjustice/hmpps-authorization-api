package uk.gov.justice.digital.hmpps.authorizationserver.security

import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletRequest
import java.time.Duration
import java.util.Optional
import java.util.stream.Stream

open class CookieHelper(protected val name: String, private val expiryTime: Duration) {

  open fun readValueFromCookie(request: HttpServletRequest): Optional<String> {
    return Stream.of(*Optional.ofNullable(request.cookies).orElse(arrayOfNulls(0)))
      .filter { c: Cookie -> name == c.name }
      .map { it.value }
      .findFirst()
  }
}
