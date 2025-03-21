package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock
import org.mockito.kotlin.whenever
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient

class SubDomainMatchingRedirectUriValidatorTest {
  private val authenticationContext: OAuth2AuthorizationCodeRequestAuthenticationContext = mock()
  private val authentication: OAuth2AuthorizationCodeRequestAuthenticationToken = mock()
  private val registeredClient: RegisteredClient = mock()
  private val principal: Authentication = mock()

  private var validator: SubDomainMatchingRedirectUriValidator? = null

  @BeforeEach
  fun setup() {
    validator = SubDomainMatchingRedirectUriValidator()
    whenever(authenticationContext.getAuthentication<Authentication>()).thenReturn(authentication)
    whenever(authenticationContext.registeredClient).thenReturn(registeredClient)
  }

  @Test
  fun `should accept redirect uri without subdomain`() {
    givenRequestedRedirectUri("https://template-typescript-dev.hmpps.service.justice.gov.uk/sign-in/callback")
    givenRegisteredRedirectUris("https://template-typescript-dev.hmpps.service.justice.gov.uk/sign-in/callback")

    validator?.accept(authenticationContext)
  }

  @Test
  fun `should accept redirect uri with subdomain`() {
    givenRequestedRedirectUri("https://sub1.template-typescript-dev.hmpps.service.justice.gov.uk/sign-in/callback")
    givenRegisteredRedirectUris("https://template-typescript-dev.hmpps.service.justice.gov.uk/sign-in/callback")

    validator?.accept(authenticationContext)
  }

  @Test
  fun `should fail when redirect uri without subdomain does not match`() {
    givenRequestedRedirectUri("https://template-typescript-dev.hmpps.service.justice.gov.uk/sign-in/callback")
    givenRegisteredRedirectUris("https://template-typescript-dev.hmpps.service.justice.gov.uk/sign-in/callbackx")
    givenExceptionDataAvailable()

    assertThatThrownBy { validator?.accept(authenticationContext) }.isInstanceOf(
      OAuth2AuthorizationCodeRequestAuthenticationException::class.java,
    )
      .withFailMessage("OAuth 2.0 Parameter: redirect_uri")
  }

  @Test
  fun `should fail when redirect uri with subdomain does not match`() {
    givenRequestedRedirectUri("https://sub1.template-typescript-dev.hmpps.service.justice.gov.uk/sign-in/callback")
    givenRegisteredRedirectUris("https://template-typescript-dev.hmpps.service.justice.gov.uk/sign-in/callbackx")
    givenExceptionDataAvailable()

    assertThatThrownBy { validator?.accept(authenticationContext) }.isInstanceOf(
      OAuth2AuthorizationCodeRequestAuthenticationException::class.java,
    )
      .withFailMessage("OAuth 2.0 Parameter: redirect_uri")
  }

  @Test
  fun `should fail when no registered redirect urls`() {
    givenRequestedRedirectUri("https://sub1.template-typescript-dev.hmpps.service.justice.gov.uk/sign-in/callback")
    givenExceptionDataAvailable()

    assertThatThrownBy { validator?.accept(authenticationContext) }.isInstanceOf(
      OAuth2AuthorizationCodeRequestAuthenticationException::class.java,
    )
      .withFailMessage("OAuth 2.0 Parameter: redirect_uri")
  }

  @Test
  fun `should fail when requested redirect uri is empty and multiple registered redirects`() {
    givenRequestedRedirectUri("")
    givenRegisteredRedirectUris("https://template-typescript-dev.hmpps.service.justice.gov.uk/sign-in/callback", "https://template-typescript-dev.hmpps.service.justice.gov.uk/sign-in/callback2")
    givenExceptionDataAvailable()

    assertThatThrownBy { validator?.accept(authenticationContext) }.isInstanceOf(
      OAuth2AuthorizationCodeRequestAuthenticationException::class.java,
    )
      .withFailMessage("OAuth 2.0 Parameter: redirect_uri")
  }

  @Test
  fun `should fail when requested redirect uri is empty and no registered redirects`() {
    givenRequestedRedirectUri("")
    givenExceptionDataAvailable()

    assertThatThrownBy { validator?.accept(authenticationContext) }.isInstanceOf(
      OAuth2AuthorizationCodeRequestAuthenticationException::class.java,
    )
      .withFailMessage("OAuth 2.0 Parameter: redirect_uri")
  }

  @Test
  fun `should fail when requested redirect uri is empty and scopes contains openid`() {
    givenRequestedRedirectUri("")
    givenRegisteredRedirectUris("https://template-typescript-dev.hmpps.service.justice.gov.uk/sign-in/callback")
    whenever(authentication.scopes).thenReturn(setOf("openid"))
    givenExceptionDataAvailable()

    assertThatThrownBy { validator?.accept(authenticationContext) }.isInstanceOf(
      OAuth2AuthorizationCodeRequestAuthenticationException::class.java,
    )
      .withFailMessage("OAuth 2.0 Parameter: redirect_uri")
  }

  @Test
  fun `should pass when requested redirect uri is empty and only one registered redirect`() {
    givenRequestedRedirectUri("")
    givenRegisteredRedirectUris("https://template-typescript-dev.hmpps.service.justice.gov.uk/sign-in/callback")

    validator?.accept(authenticationContext)
  }

  private fun givenExceptionDataAvailable() {
    whenever(authentication.principal).thenReturn(principal)
    whenever(authentication.authorizationUri).thenReturn("https://testing")
    whenever(authentication.clientId).thenReturn("testClientId")
  }

  private fun givenRegisteredRedirectUris(vararg redirectUris: String) {
    whenever(registeredClient.redirectUris).thenReturn(setOf(*redirectUris))
  }

  private fun givenRequestedRedirectUri(redirectUri: String) {
    whenever(authentication.redirectUri).thenReturn(redirectUri)
  }
}
