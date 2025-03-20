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
  fun `should accept redirect url without subdomain`() {
    givenRequestedRedirectUrl("https://template-typescript-dev.hmpps.service.justice.gov.uk/sign-in/callback")
    givenRegisteredRedirectUrls("https://template-typescript-dev.hmpps.service.justice.gov.uk/sign-in/callback")

    validator?.accept(authenticationContext)
  }

  @Test
  fun `should accept redirect url with subdomain`() {
    givenRequestedRedirectUrl("https://sub1.template-typescript-dev.hmpps.service.justice.gov.uk/sign-in/callback")
    givenRegisteredRedirectUrls("https://template-typescript-dev.hmpps.service.justice.gov.uk/sign-in/callback")

    validator?.accept(authenticationContext)
  }

  @Test
  fun `should accept loop back redirect url with matching port`() {
    givenRequestedRedirectUrl("http://127.0.0.1:9090/sign-in/callback")
    givenRegisteredRedirectUrls("http://127.0.0.1:9090/sign-in/callback")

    validator?.accept(authenticationContext)
  }

  @Test
  fun `should accept loop back redirect url without matching port`() {
    givenRequestedRedirectUrl("http://127.0.0.1:9090/sign-in/callback")
    givenRegisteredRedirectUrls("http://127.0.0.1:9999/sign-in/callback")

    validator?.accept(authenticationContext)
  }

  @Test
  fun `should fail when redirect url without subdomain does not match`() {
    givenRequestedRedirectUrl("https://template-typescript-dev.hmpps.service.justice.gov.uk/sign-in/callback")
    givenRegisteredRedirectUrls("https://template-typescript-dev.hmpps.service.justice.gov.uk/sign-in/callbackx")
    givenExceptionDataAvailable()

    assertThatThrownBy { validator?.accept(authenticationContext) }.isInstanceOf(
      OAuth2AuthorizationCodeRequestAuthenticationException::class.java,
    )
      .withFailMessage("OAuth 2.0 Parameter: redirect_uri")
  }

  @Test
  fun `should fail when redirect url with subdomain does not match`() {
    givenRequestedRedirectUrl("https://sub1.template-typescript-dev.hmpps.service.justice.gov.uk/sign-in/callback")
    givenRegisteredRedirectUrls("https://template-typescript-dev.hmpps.service.justice.gov.uk/sign-in/callbackx")
    givenExceptionDataAvailable()

    assertThatThrownBy { validator?.accept(authenticationContext) }.isInstanceOf(
      OAuth2AuthorizationCodeRequestAuthenticationException::class.java,
    )
      .withFailMessage("OAuth 2.0 Parameter: redirect_uri")
  }

  @Test
  fun `should fail when no registered redirect urls`() {
    givenRequestedRedirectUrl("https://sub1.template-typescript-dev.hmpps.service.justice.gov.uk/sign-in/callback")
    givenExceptionDataAvailable()

    assertThatThrownBy { validator?.accept(authenticationContext) }.isInstanceOf(
      OAuth2AuthorizationCodeRequestAuthenticationException::class.java,
    )
      .withFailMessage("OAuth 2.0 Parameter: redirect_uri")
  }

  @Test
  fun `should fail when requested redirect url is empty`() {
    givenRequestedRedirectUrl("")
    givenExceptionDataAvailable()

    assertThatThrownBy { validator?.accept(authenticationContext) }.isInstanceOf(
      OAuth2AuthorizationCodeRequestAuthenticationException::class.java,
    )
      .withFailMessage("OAuth 2.0 Parameter: redirect_uri")
  }

  private fun givenExceptionDataAvailable() {
    whenever(authentication.principal).thenReturn(principal)
    whenever(authentication.authorizationUri).thenReturn("https://testing")
    whenever(authentication.clientId).thenReturn("testClientId")
  }

  private fun givenRegisteredRedirectUrls(vararg redirectUris: String) {
    whenever(registeredClient.redirectUris).thenReturn(setOf(*redirectUris))
  }

  private fun givenRequestedRedirectUrl(redirectUri: String) {
    whenever(authentication.redirectUri).thenReturn(redirectUri)
  }
}
