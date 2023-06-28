package uk.gov.justice.digital.hmpps.authorizationserver.service

import org.springframework.core.convert.converter.Converter
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration

class OidcRegisteredClientConverterDecorator(private val delegateConverter: Converter<OidcClientRegistration, RegisteredClient>) : Converter<OidcClientRegistration, RegisteredClient> {

  override fun convert(clientRegistration: OidcClientRegistration): RegisteredClient? {
    val registeredClient = delegateConverter.convert(clientRegistration)
    return RegisteredClient.from(registeredClient).clientId(clientRegistration.clientId).build()
  }
}
