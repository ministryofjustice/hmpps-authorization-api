package uk.gov.justice.digital.hmpps.authorizationserver.security

import io.jsonwebtoken.JwtException
import jakarta.servlet.FilterChain
import jakarta.servlet.ServletException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.context.annotation.Configuration
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.OncePerRequestFilter
import java.io.IOException

@Configuration
class JwtCookieAuthenticationFilter(
  private val jwtCookieHelper: JwtCookieHelper,
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
    val jwt = jwtCookieHelper.readValueFromCookie(request)
    try {
      jwt.flatMap { jwtAuthenticationHelper.readAuthenticationFromJwt(it) }
        .ifPresent {
          val sc = SecurityContextHolder.getContext()
          sc.authentication = it

          // TODO do we need to use session state for this?
          // val session = request.getSession(true)
          // session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, sc)
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
}
