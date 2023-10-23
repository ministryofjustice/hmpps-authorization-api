package uk.gov.justice.digital.hmpps.authorizationserver.config

// @Configuration
// @EnableWebSecurity
class DefaultSecurityConfig {

  // @Bean
  // fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
  //   http.headers { it.frameOptions { frameOptionsCustomizer -> frameOptionsCustomizer.sameOrigin() } }
  //   http.cors { it.disable() }.csrf { it.disable() }
  //     .authorizeHttpRequests { auth ->
  //       auth.anyRequest().authenticated()
  //
  //
  //       // auth.requestMatchers(
  //       //   antMatcher("/login"),
  //       //   antMatcher("/error"),
  //       //   antMatcher("/css/**"),
  //       //   antMatcher("/js/**"),
  //       //   antMatcher("/images/**"),
  //       //   antMatcher("/fonts/**"),
  //       //   antMatcher("/webjars/**"),
  //       // ).permitAll()
  //       //
  //       // auth.requestMatchers(
  //       //   antMatcher("/h2-console/**"),
  //       //   antMatcher("/health/**"),
  //       //   antMatcher("/info"),
  //       //   antMatcher("/ping"),
  //       //   // antMatcher("/error"),
  //       //   antMatcher("/.well-known/jwks.json"),
  //       //   antMatcher("/issuer/.well-known/**"),
  //       //   antMatcher("/favicon.ico"),
  //       // ).authenticated()
  //     }
  //     .formLogin(Customizer.withDefaults())
  //   return http.build()
  // }
  //
  // @Bean
  // fun corsConfigurationSource(): CorsConfigurationSource {
  //   val source = UrlBasedCorsConfigurationSource()
  //   val corsConfig = CorsConfiguration().applyPermitDefaultValues().apply {
  //     allowedOrigins = listOf("yourAllowedOrigin.com", "127.0.0.1")
  //     allowCredentials = true
  //     allowedHeaders = listOf("Origin", "Content-Type", "Accept", "responseType", "Authorization")
  //     allowedMethods = listOf("GET", "POST", "PUT")
  //   }
  //   source.registerCorsConfiguration("/**", corsConfig)
  //   return source
  // }
}
