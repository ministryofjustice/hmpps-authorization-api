package uk.gov.justice.digital.hmpps.authorizationserver.config

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.ApplicationEventPublisher
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.core.convert.converter.Converter
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.authentication.AuthenticationEventPublisher
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
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
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationToken
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.logout.LogoutFilter
import org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationserver.security.AuthorizeLoginUrlAuthenticationEntryPoint
import uk.gov.justice.digital.hmpps.authorizationserver.security.JwtCookieAuthenticationFilter
import uk.gov.justice.digital.hmpps.authorizationserver.security.SavedRequestCookieHelper
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientCredentialsRequestValidator
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientIdService
import uk.gov.justice.digital.hmpps.authorizationserver.service.JWKKeyAccessor
import uk.gov.justice.digital.hmpps.authorizationserver.service.LoggingAuthenticationFailureHandler
import uk.gov.justice.digital.hmpps.authorizationserver.service.OAuth2AuthenticationFailureEvent
import uk.gov.justice.digital.hmpps.authorizationserver.service.OidcRegisteredClientConverterDecorator
import uk.gov.justice.digital.hmpps.authorizationserver.service.OidcRegistrationAdditionalDataHandler
import uk.gov.justice.digital.hmpps.authorizationserver.service.RegisteredClientAdditionalInformation
import uk.gov.justice.digital.hmpps.authorizationserver.service.RegisteredClientDataService
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
  private val clientIdService: ClientIdService,
  private val jwtCookieAuthenticationFilter: JwtCookieAuthenticationFilter,
  private val savedRequestCookieHelper: SavedRequestCookieHelper,
) {

  @Bean
  @Order(1)
  fun authorizationServerSecurityFilterChain(
    http: HttpSecurity,
    registeredClientAdditionalInformation: RegisteredClientAdditionalInformation,
    registeredClientDataService: RegisteredClientDataService,
    loggingAuthenticationFailureHandler: LoggingAuthenticationFailureHandler,
  ): SecurityFilterChain {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)

    http.exceptionHandling {
      it.defaultAuthenticationEntryPointFor(
        AuthorizeLoginUrlAuthenticationEntryPoint("http://localhost:9090/auth/sign-in", savedRequestCookieHelper),
        antMatcher("/oauth2/authorize"),
      )
    }

    val authorizationServerConfigurer = http.getConfigurer(OAuth2AuthorizationServerConfigurer::class.java)
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

          authenticationProviders.replaceAll { authenticationProvider ->
            withAdditionalDataHandler(authenticationProvider, registeredClientAdditionalInformation, registeredClientDataService)
          }
        }
      }
    }

    http.addFilterAfter(jwtCookieAuthenticationFilter, LogoutFilter::class.java)
      .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
    return http.build()
  }

  @Bean
  @Order(2)
  fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
    http {
      headers { frameOptions { sameOrigin = true } }
      sessionManagement { sessionCreationPolicy = SessionCreationPolicy.STATELESS }
      // Can't have CSRF protection as requires session
      csrf { disable() }
      authorizeHttpRequests {
        listOf(
          "/webjars/**",
          "/favicon.ico",
          "/csrf",
          "/health/**",
          "/info",
          "/v3/api-docs/**",
          "/swagger-ui/**",
          "/swagger-ui.html",
        ).forEach { authorize(it, permitAll) }
        authorize(anyRequest, authenticated)
      }
      oauth2ResourceServer { jwt { jwtAuthenticationConverter = AuthAwareTokenConverter() } }
    }
    return http.build()

    // http.headers { it.frameOptions { frameOptionsCustomizer -> frameOptionsCustomizer.sameOrigin() } }
    // http.cors { it.disable() }.csrf { it.disable() }
    //   .authorizeHttpRequests { auth ->
    //     auth.requestMatchers(
    //       antMatcher("/base-clients/**"),
    //       antMatcher("/clients/exists/**"),
    //     ).permitAll()
    //   }
    //   .formLogin(Customizer.withDefaults())
    // return http.build()
  }

  @Bean
  fun corsConfigurationSource(): CorsConfigurationSource {
    val source = UrlBasedCorsConfigurationSource()
    val corsConfig = CorsConfiguration().applyPermitDefaultValues().apply {
      allowedOrigins = listOf("yourAllowedOrigin.com", "127.0.0.1")
      allowCredentials = true
      allowedHeaders = listOf("Origin", "Content-Type", "Accept", "responseType", "Authorization")
      allowedMethods = listOf("GET", "POST", "PUT")
    }
    source.registerCorsConfiguration("/**", corsConfig)
    return source
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
  fun authenticationEventPublisher
  (applicationEventPublisher: ApplicationEventPublisher?): AuthenticationEventPublisher {
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
      return ClientCredentialsRequestValidator(authenticationProvider, clientConfigRepository, ipAddressHelper, clientIdService)
    }

    return authenticationProvider
  }

  private fun withAdditionalDataHandler(
    authenticationProvider: AuthenticationProvider,
    registeredClientAdditionalInformation: RegisteredClientAdditionalInformation,
    registeredClientDataService: RegisteredClientDataService,
  ): AuthenticationProvider {
    if (authenticationProvider.supports(OidcClientRegistrationAuthenticationToken::class.java)) {
      return OidcRegistrationAdditionalDataHandler(authenticationProvider, registeredClientAdditionalInformation, registeredClientDataService)
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
