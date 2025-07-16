package uk.gov.justice.digital.hmpps.authorizationapi.data.service

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.dao.DataRetrievalFailureException
import org.springframework.security.jackson2.SecurityJackson2Modules.getModules
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module
import org.springframework.util.StringUtils
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.Authorization
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.AuthorizationRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.ClientRepository
import java.time.ZoneId

class JpaOAuth2AuthorizationService(
  private val authorizationRepository: AuthorizationRepository,
  private val registeredClientRepository: JdbcRegisteredClientRepository,
) : OAuth2AuthorizationService {
  private val objectMapper = ObjectMapper()

  init {
    val classLoader: ClassLoader = ClientRepository::class.java.getClassLoader()
    objectMapper.registerModules(getModules(classLoader))
    objectMapper.registerModule(OAuth2AuthorizationServerJackson2Module())
  }

  override fun save(authorization: OAuth2Authorization) {
    authorizationRepository.save(toEntity(authorization))
  }

  override fun remove(authorization: OAuth2Authorization) {
    authorizationRepository.deleteById(authorization.id!!)
  }

  override fun findById(id: String): OAuth2Authorization? = authorizationRepository.findById(id).map { toObject(it) }.orElse(null)

  override fun findByToken(token: String, tokenType: OAuth2TokenType?): OAuth2Authorization? {
    val result: Authorization? = if (tokenType == null) {
      authorizationRepository.findByStateOrAuthorizationCodeValueOrAccessTokenValue(token)
    } else if (OAuth2ParameterNames.STATE == tokenType.value) {
      authorizationRepository.findByState(token)
    } else if (OAuth2ParameterNames.CODE == tokenType.value) {
      authorizationRepository.findByAuthorizationCodeValue(token)
    } else if (OAuth2ParameterNames.ACCESS_TOKEN == tokenType.value) {
      authorizationRepository.findByAccessTokenValue(token)
    } else {
      null
    }

    return result?.let { toObject(it) }
  }

  private fun toObject(entity: Authorization): OAuth2Authorization {
    val registeredClient = registeredClientRepository.findById(entity.registeredClientId)
      ?: throw DataRetrievalFailureException("Registered client with id ${entity.registeredClientId} not found")

    val builder = OAuth2Authorization.withRegisteredClient(registeredClient)
      .id(entity.id)
      .principalName(entity.principalName)
      .authorizationGrantType(resolveAuthorizationGrantType(entity.authorizationGrantType))
      .authorizedScopes(StringUtils.commaDelimitedListToSet(entity.authorizedScopes))
      .attributes { attributes -> attributes.putAll(parseMap(entity.attributes)) }

    if (entity.state != null) {
      builder.attribute(OAuth2ParameterNames.STATE, entity.state)
    }

    if (entity.authorizationCodeValue != null) {
      val authorizationCode = OAuth2AuthorizationCode(
        entity.authorizationCodeValue,
        entity.authorizationCodeIssuedAt?.atZone(ZoneId.systemDefault())?.toInstant(),
        entity.authorizationCodeExpiresAt?.atZone(ZoneId.systemDefault())?.toInstant(),
      )

      builder.token(authorizationCode) { metadata -> metadata.putAll(parseMap(entity.authorizationCodeMetadata)) }
    }

    if (entity.accessTokenValue != null) {
      val accessToken = OAuth2AccessToken(
        OAuth2AccessToken.TokenType.BEARER,
        entity.accessTokenValue,
        entity.accessTokenIssuedAt?.atZone(ZoneId.systemDefault())?.toInstant(),
        entity.accessTokenExpiresAt?.atZone(ZoneId.systemDefault())?.toInstant(),
        StringUtils.commaDelimitedListToSet(entity.accessTokenScopes),
      )

      builder.token(accessToken) { metadata -> metadata.putAll(parseMap(entity.accessTokenMetadata)) }
    }

    return builder.build()
  }

  private fun parseMap(data: String?): Map<String, Any> {
    if (data == null) {
      return emptyMap()
    }

    try {
      return objectMapper.readValue(data, object : TypeReference<Map<String, Any>>() {})
    } catch (ex: Exception) {
      throw IllegalArgumentException(ex.message, ex)
    }
  }

  private fun resolveAuthorizationGrantType(authorizationGrantType: String) = if (AuthorizationGrantType.AUTHORIZATION_CODE.value == authorizationGrantType) {
    AuthorizationGrantType.AUTHORIZATION_CODE
  } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.value == authorizationGrantType) {
    AuthorizationGrantType.CLIENT_CREDENTIALS
  } else {
    throw IllegalArgumentException("AuthorizationGrantType $authorizationGrantType not supported")
  }

  private fun toEntity(authorization: OAuth2Authorization): Authorization {
    with(authorization) {
      val oAuth2AuthorizationCodeToken: OAuth2Authorization.Token<OAuth2AuthorizationCode>? = getToken(OAuth2AuthorizationCode::class.java)
      val oAuth2AccessToken: OAuth2Authorization.Token<OAuth2AccessToken>? = getToken(OAuth2AccessToken::class.java)

      return Authorization(
        id = id!!,
        registeredClientId = registeredClientId,
        principalName = principalName,
        authorizationGrantType = authorizationGrantType.value,
        authorizedScopes = authorizedScopes.joinToString(separator = ","),
        attributes = writeMap(attributes)!!,
        state = getAttribute(OAuth2ParameterNames.STATE),
        authorizationCodeValue = oAuth2AuthorizationCodeToken?.token?.tokenValue,
        authorizationCodeIssuedAt = oAuth2AuthorizationCodeToken?.token?.issuedAt?.atZone(ZoneId.systemDefault())?.toLocalDateTime(),
        authorizationCodeExpiresAt = oAuth2AuthorizationCodeToken?.token?.expiresAt?.atZone(ZoneId.systemDefault())?.toLocalDateTime(),
        authorizationCodeMetadata = writeMap(oAuth2AuthorizationCodeToken?.metadata),
        accessTokenValue = oAuth2AccessToken?.token?.tokenValue,
        accessTokenIssuedAt = oAuth2AccessToken?.token?.issuedAt?.atZone(ZoneId.systemDefault())?.toLocalDateTime(),
        accessTokenExpiresAt = oAuth2AccessToken?.token?.expiresAt?.atZone(ZoneId.systemDefault())?.toLocalDateTime(),
        accessTokenMetadata = writeMap(oAuth2AccessToken?.metadata),
        accessTokenType = oAuth2AccessToken?.token?.tokenType?.value,
        accessTokenScopes = oAuth2AccessToken?.token?.scopes?.joinToString(","),
      )
    }
  }

  private fun writeMap(metadata: Map<String, Any>?): String? {
    if (metadata == null) return null
    try {
      return this.objectMapper.writeValueAsString(metadata)
    } catch (ex: Exception) {
      throw IllegalArgumentException(ex.message, ex)
    }
  }
}
