package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.slf4j.LoggerFactory
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.util.MultiValueMap
import org.springframework.util.StringUtils
import org.springframework.web.util.UriComponents
import org.springframework.web.util.UriComponentsBuilder
import java.util.function.Consumer

class SubDomainMatchingRedirectUriValidator : Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {

  companion object {
    private val log = LoggerFactory.getLogger(this::class.java)
  }

  override fun accept(authenticationContext: OAuth2AuthorizationCodeRequestAuthenticationContext) {
    val authorizationCodeRequestAuthentication =
      authenticationContext.getAuthentication<Authentication>() as OAuth2AuthorizationCodeRequestAuthenticationToken
    val registeredClient = authenticationContext.registeredClient
    val requestedRedirectUri = authorizationCodeRequestAuthentication.redirectUri

    if (StringUtils.hasText(requestedRedirectUri)) {
      var requestedRedirect: UriComponents? = null

      try {
        requestedRedirect = UriComponentsBuilder.fromUriString(requestedRedirectUri!!).build()
      } catch (_: Exception) {}

      if (requestedRedirect == null || requestedRedirect.fragment != null) {
        log.info("Invalid request: redirect_uri is missing or contains a fragment for registered client {}", registeredClient.id)
        throwError(
          authorizationCodeRequestAuthentication,
        )
      }

      if (!isLoopBackAddress(requestedRedirect!!.host)) {
        if (!redirectIncludingPortMatches(registeredClient, requestedRedirectUri!!)) {
          throwError(
            authorizationCodeRequestAuthentication,
          )
        }
      } else {
        if (!redirectMatchesWithPortLeniency(registeredClient, requestedRedirectUri!!)) {
          log.info("Invalid request: redirect_uri does not match for registered client {}", registeredClient.id)

          throwError(
            authorizationCodeRequestAuthentication,
          )
        }
      }
    } else if (authorizationCodeRequestAuthentication.scopes.contains("openid") || registeredClient.redirectUris.size != 1) {
      throwError(
        authorizationCodeRequestAuthentication,
      )
    }
  }

  private fun redirectMatchesWithPortLeniency(registeredClient: RegisteredClient, requestedRedirect: String): Boolean = registeredRedirectsContainMatch(registeredClient, requestedRedirect, false)

  private fun redirectIncludingPortMatches(registeredClient: RegisteredClient, requestedRedirect: String): Boolean = registeredRedirectsContainMatch(registeredClient, requestedRedirect, true)

  private fun registeredRedirectsContainMatch(registeredClient: RegisteredClient, requestedRedirect: String, matchPorts: Boolean): Boolean {
    registeredClient.redirectUris.forEach {
      if (redirectMatches(requestedRedirect, it, matchPorts)) {
        return true
      }
    }
    return false
  }

  private fun redirectMatches(requestedRedirect: String, redirectUri: String, matchPorts: Boolean): Boolean {
    val requestedRedirectUri = UriComponentsBuilder.fromUriString(requestedRedirect).build()
    val registeredRedirectUri = UriComponentsBuilder.fromUriString(redirectUri).build()
    val schemeMatch: Boolean = this.isEqual(registeredRedirectUri.scheme, requestedRedirectUri.scheme)
    val userInfoMatch: Boolean = this.isEqual(registeredRedirectUri.userInfo, requestedRedirectUri.userInfo)
    val hostMatch = this.hostMatches(registeredRedirectUri.host, requestedRedirectUri.host)
    val portMatch = if (matchPorts) registeredRedirectUri.port == requestedRedirectUri.port else true
    val pathMatch: Boolean = this.isEqual(
      registeredRedirectUri.path,
      requestedRedirectUri.path?.let { StringUtils.cleanPath(it) },
    )
    val queryParamMatch = this.matchQueryParams(registeredRedirectUri.queryParams, requestedRedirectUri.queryParams)
    return schemeMatch && userInfoMatch && hostMatch && portMatch && pathMatch && queryParamMatch
  }

  private fun hostMatches(registered: String?, requested: String?): Boolean = this.isEqual(registered, requested) || requested != null && requested.endsWith(".$registered")

  private fun isEqual(str1: String?, str2: String?): Boolean = if (!StringUtils.hasText(str1)) !StringUtils.hasText(str2) else (str1 == str2)

  private fun matchQueryParams(
    registeredRedirectUriQueryParams: MultiValueMap<String, String>,
    requestedRedirectUriQueryParams: MultiValueMap<String, String>,
  ): Boolean {
    for (key in registeredRedirectUriQueryParams.keys) {
      if (registeredRedirectUriQueryParams[key] != requestedRedirectUriQueryParams[key]) {
        return false
      }
    }

    return true
  }

  private fun isLoopBackAddress(host: String?): Boolean {
    if (!StringUtils.hasText(host)) {
      return false
    } else if ("[0:0:0:0:0:0:0:1]" != host && "[::1]" != host) {
      val ipv4Octets = host!!.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
      if (ipv4Octets.size != 4) {
        return false
      } else {
        try {
          val address = IntArray(ipv4Octets.size)

          for (i in ipv4Octets.indices) {
            address[i] = ipv4Octets[i].toInt()
          }

          return address[0] == 127 && address[1] >= 0 && address[1] <= 255 && address[2] >= 0 && address[2] <= 255 && address[3] >= 1 && address[3] <= 255
        } catch (var4: NumberFormatException) {
          return false
        }
      }
    } else {
      return true
    }
  }

  private fun throwError(
    authorizationCodeRequestAuthentication: OAuth2AuthorizationCodeRequestAuthenticationToken,
  ) {
    val error = OAuth2Error(
      "invalid_request",
      "OAuth 2.0 Parameter: redirect_uri",
      "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1",
    )
    throwError(error, authorizationCodeRequestAuthentication)
  }

  private fun throwError(
    error: OAuth2Error,
    authorizationCodeRequestAuthentication: OAuth2AuthorizationCodeRequestAuthenticationToken,
  ) {
    val authorizationCodeRequestAuthenticationResult = OAuth2AuthorizationCodeRequestAuthenticationToken(
      authorizationCodeRequestAuthentication.authorizationUri,
      authorizationCodeRequestAuthentication.clientId,
      authorizationCodeRequestAuthentication.principal as Authentication,
      null,
      authorizationCodeRequestAuthentication.state,
      authorizationCodeRequestAuthentication.scopes,
      authorizationCodeRequestAuthentication.additionalParameters,
    )
    authorizationCodeRequestAuthenticationResult.isAuthenticated = true
    throw OAuth2AuthorizationCodeRequestAuthenticationException(error, authorizationCodeRequestAuthenticationResult)
  }
}
