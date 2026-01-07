package uk.gov.justice.digital.hmpps.authorizationapi.service

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.server.ServletServerHttpResponse
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import java.time.temporal.ChronoUnit

class TokenResponseHandler(
  private val oAuth2AccessTokenResponseHttpMessageConverter: OAuth2AccessTokenResponseHttpMessageConverter,
  private val jwtDecoder: JwtDecoder,
) : AuthenticationSuccessHandler {
  constructor(jwtDecoder: JwtDecoder) : this(OAuth2AccessTokenResponseHttpMessageConverter(), jwtDecoder)

  override fun onAuthenticationSuccess(
    request: HttpServletRequest?,
    response: HttpServletResponse?,
    authentication: Authentication,
  ) {
    val accessTokenAuthentication = authentication as OAuth2AccessTokenAuthenticationToken
    val accessToken = accessTokenAuthentication.accessToken
    val jwt = jwtDecoder.decode(accessToken.tokenValue)
    val claims = jwt.claims

    val builder = OAuth2AccessTokenResponse.withToken(accessToken.tokenValue)
      .tokenType(accessToken.tokenType)
      .scopes(accessToken.scopes)
    if (accessToken.issuedAt != null && accessToken.expiresAt != null) {
      val exp = ChronoUnit.SECONDS.between(accessToken.issuedAt, accessToken.expiresAt)
      builder.expiresIn(exp)
    }

    val otherParams = HashMap<String, Any>()
    claims["sub"]?.let { otherParams["sub"] = it }

    claims["scope"]?.let {
      if (it is List<*>) {
        val scopes = it.filterIsInstance<String>().toCollection(mutableSetOf())
        if (scopes.isNotEmpty()) {
          otherParams["scope"] = scopes.joinToString(" ")
        }
      }
    }

    claims["jti"]?.let { otherParams["jti"] = it }
    claims["auth_source"]?.let { otherParams["auth_source"] = it }
    claims["iss"]?.let { otherParams["iss"] = it }
    claims["user_uuid"]?.let { otherParams["user_uuid"] = it }
    claims["user_id"]?.let { otherParams["user_id"] = it }
    claims["user_name"]?.let { otherParams["user_name"] = it }
    claims["name"]?.let { otherParams["name"] = it }
    claims["jwt_id"]?.let { otherParams["jwt_id"] = it }

    val additionalParameters = accessTokenAuthentication.additionalParameters
    if (additionalParameters.isNotEmpty()) {
      otherParams.putAll(additionalParameters)
    }
    builder.additionalParameters(otherParams)

    val accessTokenResponse = builder.build()
    val httpResponse = ServletServerHttpResponse(response)
    oAuth2AccessTokenResponseHttpMessageConverter.write(accessTokenResponse, null, httpResponse)
  }
}
