package uk.gov.justice.digital.hmpps.hmppsauthorizationserver.config

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings
import org.springframework.security.oauth2.server.authorization.config.TokenSettings
import org.springframework.security.web.SecurityFilterChain
import uk.gov.justice.digital.hmpps.hmppsauthorizationserver.service.KeyGeneratorUtils
import java.time.Duration
import java.util.*

@Configuration(proxyBeanMethods = false)
class AuthorizationServerConfig {

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http.cors().and())

    http.cors().and().csrf().disable()
      .formLogin(withDefaults<FormLoginConfigurer<HttpSecurity>>())

    return http.build()
  }

  @Bean
  fun jwkSource(): JWKSource<SecurityContext> {
    val rsaKey = KeyGeneratorUtils.generateRSAKey()
    val jwkSet = JWKSet(rsaKey)
    return JWKSource<SecurityContext> { jwkSelector, _ -> jwkSelector.select(jwkSet) }
  }

  @Bean
  fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
  }

  @Bean
  fun providerSettings(): ProviderSettings {
    return ProviderSettings.builder().issuer("http://authorization-server:8089").build()
  }

  @Bean
  fun passwordEncoder() = BCryptPasswordEncoder(10)

  @Bean
  fun registeredClientRepository(
    jdbcTemplate: JdbcTemplate,
    passwordEncoder: BCryptPasswordEncoder
  ): RegisteredClientRepository {
    val registeredClientRepository = JdbcRegisteredClientRepository(jdbcTemplate)
    val registeredClientParametersMapper = JdbcRegisteredClientRepository.RegisteredClientParametersMapper()
    val yourClientId = "test-client-id"
    val yourSecret = BCryptPasswordEncoder(10).encode("test-secret")

    registeredClientParametersMapper.setPasswordEncoder(passwordEncoder)
    registeredClientRepository.setRegisteredClientParametersMapper(registeredClientParametersMapper)

    if (registeredClientRepository.findByClientId(yourClientId) == null) {
      val registeredClient: RegisteredClient = RegisteredClient.withId(UUID.randomUUID().toString())
        .tokenSettings(
          TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(5))
            .refreshTokenTimeToLive(Duration.ofMinutes(10))
            .build()
        )
        .clientId(yourClientId)
        .clientSecret(yourSecret)
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .redirectUri("http://127.0.0.1:8089/authorized")
        .redirectUri("https://oauth.pstmn.io/v1/callback")
        .scope(OidcScopes.OPENID)
        .scope("test-application.read")
        .scope("test-application.write")
        .build()

      registeredClientRepository.save(registeredClient)
    }

    return registeredClientRepository
  }

  @Bean
  fun authorizationService(
    jdbcTemplate: JdbcTemplate,
    registeredClientRepository: RegisteredClientRepository
  ): OAuth2AuthorizationService {
    return JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository)
  }
}