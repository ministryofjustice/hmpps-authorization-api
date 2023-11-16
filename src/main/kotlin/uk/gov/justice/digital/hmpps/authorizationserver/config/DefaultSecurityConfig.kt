package uk.gov.justice.digital.hmpps.authorizationserver.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
@EnableWebSecurity
class DefaultSecurityConfig {

  @Bean
  fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
    http.headers { it.frameOptions { frameOptionsCustomizer -> frameOptionsCustomizer.disable() } }
    http.cors { it.disable() }.csrf { it.disable() }
      .authorizeHttpRequests { auth ->
        auth.requestMatchers(
          antMatcher("/h2-console/**"),
          antMatcher("/health/**"),
          antMatcher("/info"),
          antMatcher("/ping"),
          antMatcher("/error"),
          antMatcher("/.well-known/jwks.json"),
          antMatcher("/jwt-public-key"),
          antMatcher("/issuer/.well-known/**"),
          antMatcher("/favicon.ico"),
        ).permitAll().anyRequest().authenticated()
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
