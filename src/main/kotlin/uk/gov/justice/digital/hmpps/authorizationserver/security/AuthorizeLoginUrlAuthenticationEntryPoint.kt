package uk.gov.justice.digital.hmpps.authorizationserver.security

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.web.util.UriComponentsBuilder
import java.net.URI
import java.net.URISyntaxException
import java.util.Base64.getEncoder

class AuthorizeLoginUrlAuthenticationEntryPoint(loginFormUrl: String, private val savedRequestCookieHelper: CookieHelper) :
  LoginUrlAuthenticationEntryPoint(loginFormUrl) {

  override fun commence(
    request: HttpServletRequest,
    response: HttpServletResponse,
    authException: AuthenticationException?,
  ) {
    saveRequest(request, response)
    super.commence(request, response, authException)
  }

  private fun saveRequest(request: HttpServletRequest, response: HttpServletResponse) {
    val redirectUrl = buildUrlFromRequest(request)
    val redirectUrlBase64 = getEncoder().encodeToString(redirectUrl.toByteArray())
    savedRequestCookieHelper.addCookieToResponse(request, response, redirectUrlBase64)
  }

  private fun buildUrlFromRequest(request: HttpServletRequest): String {
    val requestUrl = request.requestURL.toString()
    val requestUri: URI = try {
      URI(requestUrl)
    } catch (e: URISyntaxException) {
      throw RuntimeException("Problem creating URI from request.getRequestURL() = [$requestUrl]", e)
    }
    val uriComponentsBuilder = UriComponentsBuilder.newInstance()
      .scheme(if (request.isSecure) "https" else "http")
      .host(requestUri.host)
      .path(requestUri.path)
      .query(request.queryString)

    if (request.isSecure && requestUri.port != 443 || !request.isSecure && requestUri.port != 80) {
      uriComponentsBuilder.port(requestUri.port)
    }
    return uriComponentsBuilder.build().toUriString()
  }
}
