package uk.gov.justice.digital.hmpps.hmppsauthorizationserver.config

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
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings
import org.springframework.security.web.SecurityFilterChain
import uk.gov.justice.digital.hmpps.hmppsauthorizationserver.service.KeyPairAccessor
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.UUID

@Configuration(proxyBeanMethods = false)
class AuthorizationServerConfig(
  @Value("\${jwt.jwk.key.id}") private val keyId: String,
) {

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http.cors().and())

    http.cors().and().csrf().disable()
      .formLogin(withDefaults<FormLoginConfigurer<HttpSecurity>>())

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
      .keyID(UUID.randomUUID().toString())
      .build()

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
  fun userDetailsService(jdbcTemplate: JdbcTemplate): UserDetailsService {
    val userDetailsService = JdbcDaoImpl()
    userDetailsService.jdbcTemplate = jdbcTemplate
    return userDetailsService
  }
}
