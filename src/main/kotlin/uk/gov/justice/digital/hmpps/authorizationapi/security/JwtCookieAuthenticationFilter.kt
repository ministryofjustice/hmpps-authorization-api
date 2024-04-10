package uk.gov.justice.digital.hmpps.authorizationapi.security

import io.jsonwebtoken.JwtException
import jakarta.servlet.FilterChain
import jakarta.servlet.ServletException
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.io.IOException
import java.util.Optional
import java.util.stream.Stream

@Component
class JwtCookieAuthenticationFilter(
  private val jwtAuthenticationHelper: JwtAuthenticationHelper,
) : OncePerRequestFilter() {

  companion object {
    private val log = LoggerFactory.getLogger(this::class.java)
  }

  @Throws(ServletException::class, IOException::class)
  override fun doFilterInternal(
    request: HttpServletRequest,
    response: HttpServletResponse,
    filterChain: FilterChain,
  ) {
    val jwt = readValueFromCookie(request)
    try {
      jwt.flatMap { jwtAuthenticationHelper.readAuthenticationFromJwt(it) }
        .ifPresent {
          val sc = SecurityContextHolder.getContext()
          sc.authentication = it
        }
    } catch (e: JwtException) {
      log.info("Unable to read authentication from JWT", e)
    } catch (e: Exception) {
      // filter errors don't get logged by spring boot, so log here
      log.error("Failed to read authentication due to {}", e.javaClass.name, e)
      throw e
    }
    filterChain.doFilter(request, response)
  }

  private fun readValueFromCookie(request: HttpServletRequest): Optional<String> {
    return Stream.of(*Optional.ofNullable(request.cookies).orElse(arrayOfNulls(0)))
      .filter { c: Cookie -> "jwtSession" == c.name }
      .map { it.value }
      .findFirst()
  }
}
