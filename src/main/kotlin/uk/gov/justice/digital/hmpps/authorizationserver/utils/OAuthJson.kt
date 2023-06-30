package uk.gov.justice.digital.hmpps.authorizationserver.utils

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.security.jackson2.SecurityJackson2Modules
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module
import org.springframework.stereotype.Component

@Component
class OAuthJson {

  private val objectMapper = ObjectMapper()

  /**
   * Initialise the ObjectMapper identically to the Spring Authorization Server library.
   * Note that hiding the ObjectMapper in this wrapper class prevents interference with
   * the default ObjectMapper used by Spring Boot.
   */
  init {
    val classLoader = OAuth2AuthorizationServerJackson2Module::class.java.classLoader
    val securityModules = SecurityJackson2Modules.getModules(classLoader)
    objectMapper.registerModules(securityModules)
    objectMapper.registerModule(OAuth2AuthorizationServerJackson2Module())
  }

  fun toJsonString(data: Any?): String? {
    data?.let {
      return objectMapper.writeValueAsString(data)
    }
    return null
  }

  fun <T> readValueFrom(data: String?, valueType: Class<T>): T? {
    data?.let {
      return objectMapper.readValue(data, valueType)
    }
    return null
  }
}
