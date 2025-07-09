package uk.gov.justice.digital.hmpps.authorizationapi.integration

import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import java.time.LocalDateTime
import java.time.ZoneId
import java.util.*

class JpaOAuth2AuthorizationServiceIntTest : IntegrationTestBase() {

  @Autowired
  private lateinit var authorizationService: OAuth2AuthorizationService

  @Autowired
  private lateinit var registeredClientRepository: JdbcRegisteredClientRepository

  @Test
  fun shouldManageAuthorizations() {
    val oAuth2Authorization = createOAuth2Authorization()
    authorizationService.save(oAuth2Authorization)

    val retrieved = authorizationService.findById(oAuth2Authorization.id)
    assertNotNull(retrieved)
    assertTrue(oAuth2Authorization == retrieved)

    val retrievedByToken = authorizationService.findByToken("1234-test-access-token-1234", OAuth2TokenType.ACCESS_TOKEN)
    assertNotNull(retrievedByToken)
    assertTrue(oAuth2Authorization == retrievedByToken)

    val retrievedByAuthorizationCode = authorizationService.findByToken("1234-test-authorization-code-1234", OAuth2TokenType(OAuth2ParameterNames.CODE))
    assertNotNull(retrievedByAuthorizationCode)
    assertTrue(oAuth2Authorization == retrievedByAuthorizationCode)

    val retrievedWithoutTokenType = authorizationService.findByToken("1234-test-authorization-code-1234", null)
    assertNotNull(retrievedWithoutTokenType)
    assertTrue(oAuth2Authorization == retrievedWithoutTokenType)

    authorizationService.remove(retrievedWithoutTokenType)
    val removed = authorizationService.findById(oAuth2Authorization.id)
    assertNull(removed)
  }

  private fun createOAuth2Authorization(): OAuth2Authorization {
    val registeredClient = registeredClientRepository.findByClientId("test-auth-code-client")
    val authorizationId = UUID.randomUUID().toString()

    val oAuth2AccessToken = OAuth2AccessToken(
      OAuth2AccessToken.TokenType.BEARER,
      "1234-test-access-token-1234",
      LocalDateTime.now().minusDays(1).atZone(ZoneId.systemDefault()).toInstant(),
      LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant(),
      setOf("read", "write"),
    )

    val authorizationCode = OAuth2AuthorizationCode(
      "1234-test-authorization-code-1234",
      LocalDateTime.now().minusDays(1).atZone(ZoneId.systemDefault()).toInstant(),
      LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant(),
    )

    return OAuth2Authorization.withRegisteredClient(registeredClient)
      .id(authorizationId)
      .principalName("testy")
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .authorizedScopes(setOf("read", "write"))
      .attributes { attributes -> attributes.putAll(mapOf("attrib1" to "attrib1-value", "attrib2" to "attrib2-value")) }
      .token(oAuth2AccessToken) { metadata -> metadata.putAll(mapOf("metadata1" to "metadata1-value")) }
      .token(authorizationCode) { metadata -> metadata.putAll(mapOf("metadata1" to "metadata1-value")) }
      .build()
  }
}
