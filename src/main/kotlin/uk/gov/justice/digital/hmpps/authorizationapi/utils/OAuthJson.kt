package uk.gov.justice.digital.hmpps.authorizationapi.utils

import org.springframework.security.jackson.SecurityJacksonModules
import org.springframework.security.oauth2.server.authorization.jackson.OAuth2AuthorizationServerJacksonModule
import org.springframework.stereotype.Component
import tools.jackson.databind.json.JsonMapper
import tools.jackson.module.kotlin.KotlinModule
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientRepository

@Component
class OAuthJson {

  /**
   * Initialise the ObjectMapper identically to the Spring Authorization Server library.
   * Note that hiding the ObjectMapper in this wrapper class prevents interference with
   * the default ObjectMapper used by Spring Boot.
   */
  private val objectMapper: JsonMapper = run {
    val classLoader: ClassLoader = ClientRepository::class.java.classLoader
    JsonMapper.builder()
      .addModule(KotlinModule.Builder().build())
      .addModules(SecurityJacksonModules.getModules(classLoader))
      .addModule(OAuth2AuthorizationServerJacksonModule())
      .build()
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
