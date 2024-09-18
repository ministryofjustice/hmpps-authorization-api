package uk.gov.justice.digital.hmpps.authorizationapi.service

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.json.JSONObject
import org.springframework.http.server.ServletServerHttpResponse
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import java.time.temporal.ChronoUnit
import java.util.Base64

class TokenResponseHandler(private val oAuth2AccessTokenResponseHttpMessageConverter: OAuth2AccessTokenResponseHttpMessageConverter) :
  AuthenticationSuccessHandler {
  constructor() : this(OAuth2AccessTokenResponseHttpMessageConverter())

  override fun onAuthenticationSuccess(
    request: HttpServletRequest?,
    response: HttpServletResponse?,
    authentication: Authentication,
  ) {
    val accessTokenAuthentication = authentication as OAuth2AccessTokenAuthenticationToken
    val accessToken = accessTokenAuthentication.accessToken
    val token = getToken(accessToken.tokenValue)
    val builder = OAuth2AccessTokenResponse.withToken(accessToken.tokenValue)
      .tokenType(accessToken.tokenType)
      .scopes(accessToken.scopes)
    if (accessToken.issuedAt != null && accessToken.expiresAt != null) {
      val exp = ChronoUnit.SECONDS.between(accessToken.issuedAt, accessToken.expiresAt)
      builder.expiresIn(exp)
    }

    val otherParams = HashMap<String, Any>()

    token.optString("sub", null)?.let { otherParams["sub"] = token.get("sub").toString() }

    token.optJSONArray("scope", null)?.let { scopesArray ->
      val result = scopesArray.filterIsInstance<String>().toCollection(mutableSetOf())

      if (result.isNotEmpty()) {
        otherParams["scope"] = result.joinToString(" ")
      }
    }

    token.optString("jti", null)?.let { otherParams["jti"] = token.get("jti").toString() }
    token.optString("auth_source", null)?.let { otherParams["auth_source"] = token.get("auth_source").toString() }
    token.optString("iss", null)?.let { otherParams["iss"] = token.get("iss").toString() }
    token.optString("user_uuid", null)?.let { otherParams["user_uuid"] = token.get("user_uuid").toString() }
    token.optString("user_id", null)?.let { otherParams["user_id"] = token.get("user_id").toString() }
    token.optString("user_name", null)?.let { otherParams["user_name"] = token.get("user_name").toString() }
    token.optString("name", null)?.let { otherParams["name"] = token.get("name").toString() }
    token.optString("jwt_id", null)?.let { otherParams["jwt_id"] = token.get("jwt_id").toString() }

    val additionalParameters = accessTokenAuthentication.additionalParameters
    if (additionalParameters.isNotEmpty()) {
      otherParams.putAll(additionalParameters)
    }
    builder.additionalParameters(otherParams)

    val accessTokenResponse = builder.build()
    val httpResponse = ServletServerHttpResponse(response)
    oAuth2AccessTokenResponseHttpMessageConverter.write(accessTokenResponse, null, httpResponse)
  }

  private fun getToken(accessToken: String): JSONObject {
    val tokenParts = accessToken.split(".")
    return JSONObject(String(Base64.getDecoder().decode(tokenParts[1])))
  }
}
