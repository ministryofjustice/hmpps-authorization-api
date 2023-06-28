package uk.gov.justice.digital.hmpps.authorizationserver.config

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.core.convert.converter.Converter
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.DelegatingPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.web.SecurityFilterChain
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientCredentialsRequestValidator
import uk.gov.justice.digital.hmpps.authorizationserver.service.KeyPairAccessor
import uk.gov.justice.digital.hmpps.authorizationserver.service.OidcRegisteredClientConverterDecorator
import uk.gov.justice.digital.hmpps.authorizationserver.utils.IpAddressHelper
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, proxyTargetClass = true)
@Configuration(proxyBeanMethods = false)
class AuthorizationServerConfig(
  @Value("\${jwt.jwk.key.id}") private val keyId: String,
  @Value("\${server.base-url}") private val baseUrl: String,
  @Value("\${server.servlet.context-path}") private val contextPath: String,

  private val clientConfigRepository: ClientConfigRepository,
  private val ipAddressHelper: IpAddressHelper,
) {

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
    val authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer()
    http.apply(authorizationServerConfigurer)
    authorizationServerConfigurer.tokenEndpoint { tokenEndpointConfigurer ->
      tokenEndpointConfigurer.authenticationProviders {
          authenticationProviders ->
        authenticationProviders.replaceAll { authenticationProvider -> withRequestValidatorForClientCredentials(authenticationProvider) }
      }
    }

    http.oauth2ResourceServer { resourceServer -> resourceServer.jwt { jwtCustomizer -> jwtCustomizer.jwtAuthenticationConverter(AuthAwareTokenConverter()) } }

    authorizationServerConfigurer.oidc { oidcCustomizer ->
      oidcCustomizer.clientRegistrationEndpoint { clientRegistrationEndpoint ->
        clientRegistrationEndpoint.authenticationProviders { authenticationProviders ->
          authenticationProviders.filterIsInstance<OidcClientRegistrationAuthenticationProvider>()[0].let {
            val registeredClientConverter = it.getRegisteredClientConverter()
            it.setRegisteredClientConverter(OidcRegisteredClientConverterDecorator(registeredClientConverter))
          }
        }
      }
    }

    // TODO - confirm cors and csrf configuration
    http.cors { it.disable() }
    http.csrf { it.disable() }

    return http.build()
  }

  @Bean
  fun jwkSet(keyPairAccessor: KeyPairAccessor): JWKSet {
    val builder = RSAKey.Builder(keyPairAccessor.getKeyPair().public as RSAPublicKey)
      .keyUse(KeyUse.SIGNATURE)
      .algorithm(JWSAlgorithm.RS256)
      .keyID(keyId)
    return JWKSet(builder.build())
  }

  @Bean
  fun jwkSource(keyPairAccessor: KeyPairAccessor): JWKSource<SecurityContext> {
    val keyPair = keyPairAccessor.getKeyPair()
    val rsaKey = RSAKey.Builder(keyPair.public as RSAPublicKey)
      .privateKey(keyPair.private as RSAPrivateKey)
      .keyID(keyId)
      .build()

    val jwkSet = JWKSet(rsaKey)
    return JWKSource<SecurityContext> { jwkSelector, _ -> jwkSelector.select(jwkSet) }
  }

  @Bean
  fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
  }

  @Bean
  fun providerSettings(): AuthorizationServerSettings {
    return AuthorizationServerSettings.builder().issuer("$baseUrl$contextPath").build()
  }

  @Bean
  fun passwordEncoder(): PasswordEncoder {
    val idForEncode = "bcrypt"
    val encoders: MutableMap<String, PasswordEncoder> = mutableMapOf()
    // NOTE: Further encoders could be added here if required
    encoders[idForEncode] = BCryptPasswordEncoder(10)
    return DelegatingPasswordEncoder(idForEncode, encoders)
  }

  @Bean
  fun registeredClientRepository(jdbcTemplate: JdbcTemplate) = JdbcRegisteredClientRepository(jdbcTemplate)

  @Bean
  fun authorizationService(jdbcTemplate: JdbcTemplate, registeredClientRepository: RegisteredClientRepository): OAuth2AuthorizationService {
    return JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository)
  }

  @Bean
  fun authorizationConsentService(
    jdbcTemplate: JdbcTemplate,
    registeredClientRepository: RegisteredClientRepository,
  ): OAuth2AuthorizationConsentService {
    return JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository)
  }

  @Bean
  fun userDetailsService(jdbcTemplate: JdbcTemplate): UserDetailsService {
    val userDetailsService = JdbcDaoImpl()
    userDetailsService.jdbcTemplate = jdbcTemplate
    return userDetailsService
  }

  private fun withRequestValidatorForClientCredentials(authenticationProvider: AuthenticationProvider): AuthenticationProvider {
    if (authenticationProvider.supports(OAuth2ClientCredentialsAuthenticationToken::class.java)) {
      return ClientCredentialsRequestValidator(authenticationProvider, clientConfigRepository, ipAddressHelper)
    }

    return authenticationProvider
  }

  private fun OidcClientRegistrationAuthenticationProvider.getRegisteredClientConverter(): Converter<OidcClientRegistration, RegisteredClient> {
    val converter =
      OidcClientRegistrationAuthenticationProvider::class.java.getDeclaredField("registeredClientConverter").let {
        it.isAccessible = true
        return@let it.get(this)
      }

    @Suppress("UNCHECKED_CAST")
    return converter as Converter<OidcClientRegistration, RegisteredClient>
  }
}
