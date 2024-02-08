package uk.gov.justice.digital.hmpps.authorizationserver.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
@EnableWebSecurity
class DefaultSecurityConfig {

  @Bean
  fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
    http {
      headers { frameOptions { sameOrigin = true } }
      sessionManagement { sessionCreationPolicy = SessionCreationPolicy.STATELESS }
      // Can't have CSRF protection as requires session
      csrf { disable() }
      authorizeHttpRequests {
        listOf(
          "/h2-console/**",
          "/webjars/**",
          "/favicon.ico",
          "/csrf",
          "/health/**",
          "/info",
          "/ping",
          "/error",
          "/.well-known/jwks.json",
          "/jwt-public-key",
          "/issuer/.well-known/**",

        ).forEach { authorize(it, permitAll) }
        authorize(anyRequest, authenticated)
      }
      oauth2ResourceServer { jwt { jwtAuthenticationConverter = AuthAwareTokenConverter() } }
    }
    return http.build()
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
}
