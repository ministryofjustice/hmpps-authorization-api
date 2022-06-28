package uk.gov.justice.digital.hmpps.authorizationserver.config

import org.springframework.context.annotation.Bean
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@EnableWebSecurity
class DefaultSecurityConfig {

  @Bean
  fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
    http.headers().frameOptions().sameOrigin()
    http.cors().and().csrf().disable()
      .authorizeRequests { auth ->
        auth.antMatchers(
          "/h2-console/**",
          "/login",
          "/css/**",
          "/js/**",
          "/images/**",
          "/fonts/**",
          "/webjars/**",
          "/health/**",
          "/info",
          "/ping",
          "/error",
          "/favicon.ico"
        ).permitAll().anyRequest().authenticated()
      }
      .formLogin(Customizer.withDefaults())
    return http.build()
  }

  @Bean
  protected fun corsConfigurationSource(): CorsConfigurationSource {
    val source = UrlBasedCorsConfigurationSource()
    val corsConfig = CorsConfiguration().applyPermitDefaultValues().apply {
      allowedOrigins = listOf("yourAllowedOrigin.com", "127.0.0.1")
      allowCredentials = true
      allowedHeaders = listOf("Origin", "Content-Type", "Accept", "responseType", "Authorization")
      allowedMethods = listOf("GET", "POST", "PUT", "OPTIONS", "DELETE", "PATCH")
    }
    source.registerCorsConfiguration("/**", corsConfig)
    return source
  }
}
