package uk.gov.justice.digital.hmpps.authorizationapi.config

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import net.javacrumbs.shedlock.core.LockProvider
import net.javacrumbs.shedlock.provider.jdbctemplate.JdbcTemplateLockProvider
import net.javacrumbs.shedlock.spring.annotation.EnableSchedulerLock
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.security.SecurityProperties
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.ApplicationEventPublisher
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.scheduling.annotation.EnableScheduling
import org.springframework.security.authentication.AuthenticationEventPublisher
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.DelegatingPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.logout.LogoutFilter
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.UserAuthorizationCodeRepository
import uk.gov.justice.digital.hmpps.authorizationapi.security.JwtCookieAuthenticationFilter
import uk.gov.justice.digital.hmpps.authorizationapi.security.OAuthAuthorizationCodeFilter
import uk.gov.justice.digital.hmpps.authorizationapi.security.SignedJwtParser
import uk.gov.justice.digital.hmpps.authorizationapi.service.ClientCredentialsRequestValidator
import uk.gov.justice.digital.hmpps.authorizationapi.service.ClientIdService
import uk.gov.justice.digital.hmpps.authorizationapi.service.ClientSecretBasicBase64OnlyAuthenticationConverter
import uk.gov.justice.digital.hmpps.authorizationapi.service.JWKKeyAccessor
import uk.gov.justice.digital.hmpps.authorizationapi.service.LoggingAuthenticationFailureHandler
import uk.gov.justice.digital.hmpps.authorizationapi.service.OAuth2AuthenticationFailureEvent
import uk.gov.justice.digital.hmpps.authorizationapi.service.RegisteredClientAdditionalInformation
import uk.gov.justice.digital.hmpps.authorizationapi.service.RegisteredClientDataService
import uk.gov.justice.digital.hmpps.authorizationapi.service.TokenResponseHandler
import uk.gov.justice.digital.hmpps.authorizationapi.service.UrlDecodingRetryClientSecretAuthenticationProvider
import uk.gov.justice.digital.hmpps.authorizationapi.service.UserAuthenticationService
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, proxyTargetClass = true)
@EnableScheduling
@EnableSchedulerLock(defaultLockAtMostFor = "PT50M", defaultLockAtLeastFor = "PT3M")
@Configuration(proxyBeanMethods = false)
class AuthorizationApiConfig(
  @Value("\${jwt.jwk.key.id}") private val keyId: String,
  @Value("\${server.base-url}") private val baseUrl: String,
  @Value("\${server.servlet.context-path}") private val contextPath: String,
  private val clientConfigRepository: ClientConfigRepository,
  private val clientIdService: ClientIdService,
  private val jwtCookieAuthenticationFilter: JwtCookieAuthenticationFilter,
) {

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  fun authorizationApiSecurityFilterChain(
    http: HttpSecurity,
    registeredClientAdditionalInformation: RegisteredClientAdditionalInformation,
    registeredClientDataService: RegisteredClientDataService,
    loggingAuthenticationFailureHandler: LoggingAuthenticationFailureHandler,
  ): SecurityFilterChain {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)
    val authorizationServerConfigurer = http.getConfigurer(OAuth2AuthorizationServerConfigurer::class.java)

    authorizationServerConfigurer.clientAuthentication { clientAuthenticationCustomizer ->

      clientAuthenticationCustomizer.authenticationConverters { converters ->
        converters.replaceAll { converter -> if (converter is ClientSecretBasicAuthenticationConverter) ClientSecretBasicBase64OnlyAuthenticationConverter() else converter }
      }

      clientAuthenticationCustomizer.authenticationProviders {
          authenticationProviders ->
        authenticationProviders.replaceAll { authenticationProvider -> withUrlDecodingRetryClientSecretAuthenticationProvider(authenticationProvider) }
      }
    }

    authorizationServerConfigurer.tokenEndpoint { tokenEndpointConfigurer ->
      tokenEndpointConfigurer.authenticationProviders {
          authenticationProviders ->
        authenticationProviders.replaceAll { authenticationProvider -> withRequestValidatorForClientCredentials(authenticationProvider) }
      }

      tokenEndpointConfigurer.accessTokenResponseHandler(TokenResponseHandler())
    }
    http
      .addFilterAfter(jwtCookieAuthenticationFilter, LogoutFilter::class.java)
      .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
      .cors { it.disable() }.csrf { it.disable() }

    return http.build()
  }

  @Bean
  fun authorizeFilter(signedJwtParser: SignedJwtParser): FilterRegistrationBean<OAuthAuthorizationCodeFilter> {
    val registrationBean = FilterRegistrationBean<OAuthAuthorizationCodeFilter>()
    registrationBean.filter = OAuthAuthorizationCodeFilter(signedJwtParser)
    registrationBean.addUrlPatterns("/oauth2/authorize")
    registrationBean.order = SecurityProperties.DEFAULT_FILTER_ORDER - 1
    return registrationBean
  }

  @Bean
  fun jwkSet(jwkKeyAccessor: JWKKeyAccessor): JWKSet {
    val jwkSet = JWKSet(
      buildList {
        add(jwkKeyAccessor.getPrimaryPublicKey())
        jwkKeyAccessor.getAuxiliaryPublicKey()?.let { add(it) }
      },
    )
    return jwkSet
  }

  @Bean
  fun jwkSource(jwkKeyAccessor: JWKKeyAccessor): JWKSource<SecurityContext> {
    val keyPair = jwkKeyAccessor.getPrimaryKeyPair()
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
  fun authenticationEventPublisher(applicationEventPublisher: ApplicationEventPublisher?): AuthenticationEventPublisher {
    // Note: DefaultAuthenticationEventPublisher provides a mapping between a number of exception types and corresponding events.
    // We could set up subscriptions (very simple using @EventListener annotation) to any of these as necessary,
    // plus add additional mappings, as below.
    val eventPublisher = DefaultAuthenticationEventPublisher(applicationEventPublisher)
    eventPublisher.setAdditionalExceptionMappings(
      mapOf(OAuth2AuthenticationException::class.java to OAuth2AuthenticationFailureEvent::class.java),
    )
    return eventPublisher
  }

  @Bean
  fun registeredClientRepository(jdbcTemplate: JdbcTemplate) = JdbcRegisteredClientRepository(jdbcTemplate)

  @Bean
  fun authorizationService(jdbcTemplate: JdbcTemplate, registeredClientRepository: RegisteredClientRepository, userAuthorizationCodeRepository: UserAuthorizationCodeRepository): OAuth2AuthorizationService {
    return UserAuthenticationService(JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository), userAuthorizationCodeRepository)
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

  @Bean
  fun lockProvider(jdbcTemplate: JdbcTemplate): LockProvider {
    return JdbcTemplateLockProvider(
      JdbcTemplateLockProvider.Configuration.builder()
        .withTableName("scheduled_job_lock")
        .withJdbcTemplate(jdbcTemplate)
        .usingDbTime()
        .build(),
    )
  }

  private fun withUrlDecodingRetryClientSecretAuthenticationProvider(authenticationProvider: AuthenticationProvider): AuthenticationProvider {
    if (authenticationProvider is ClientSecretAuthenticationProvider) {
      return UrlDecodingRetryClientSecretAuthenticationProvider(authenticationProvider)
    }
    return authenticationProvider
  }

  private fun withRequestValidatorForClientCredentials(authenticationProvider: AuthenticationProvider): AuthenticationProvider {
    if (authenticationProvider.supports(OAuth2ClientCredentialsAuthenticationToken::class.java)) {
      return ClientCredentialsRequestValidator(authenticationProvider, clientConfigRepository, clientIdService)
    }

    return authenticationProvider
  }
}
