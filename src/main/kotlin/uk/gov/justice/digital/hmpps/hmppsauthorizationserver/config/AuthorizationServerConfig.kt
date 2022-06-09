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
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings
import org.springframework.security.web.SecurityFilterChain
import uk.gov.justice.digital.hmpps.hmppsauthorizationserver.service.KeyGeneratorUtils
import java.util.stream.Collectors

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
    registeredClientParametersMapper.setPasswordEncoder(passwordEncoder)
    registeredClientRepository.setRegisteredClientParametersMapper(registeredClientParametersMapper)
    return registeredClientRepository
  }

  @Bean
  fun authorizationService(
    jdbcTemplate: JdbcTemplate,
    registeredClientRepository: RegisteredClientRepository
  ): OAuth2AuthorizationService {
    return JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository)
  }

  @Bean
  fun authorizationConsentService(
    jdbcTemplate: JdbcTemplate,
    registeredClientRepository: RegisteredClientRepository
  ): OAuth2AuthorizationConsentService {
    return JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository)
  }

  @Bean
  fun jwtCustomizer(authorizationConsentService: OAuth2AuthorizationConsentService): OAuth2TokenCustomizer<JwtEncodingContext>? {
    return OAuth2TokenCustomizer { context: JwtEncodingContext ->

      if (context.getPrincipal<Authentication>() is OAuth2ClientAuthenticationToken) {
        val principal = context.getPrincipal<Authentication>() as OAuth2ClientAuthenticationToken

        if (principal.registeredClient != null) {
          val oAuth2AuthorizationConsent = authorizationConsentService.findById(
            principal.registeredClient!!.id,
            principal.registeredClient!!.clientName
          )

          // TODO this will produce token without any authorities when none registered, confirm this is OK
          oAuth2AuthorizationConsent?.let {
            val authorities = it.authorities.stream().map { obj: GrantedAuthority -> obj.authority }
              .collect(Collectors.toSet())
            context.claims.claim("authorities", authorities)
          }
        }
      }
    }
  }
}
