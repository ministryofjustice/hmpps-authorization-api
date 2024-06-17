package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.ArgumentCaptor
import org.mockito.kotlin.inOrder
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.verifyNoInteractions
import org.mockito.kotlin.verifyNoMoreInteractions
import org.mockito.kotlin.whenever
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.UserAuthorizationCode
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.UserAuthorizationCodeRepository
import uk.gov.justice.digital.hmpps.authorizationapi.security.AuthenticatedUserDetails
import java.util.UUID

class UserAuthenticationServiceTest {

  private val delegateOAuth2AuthorizationService: OAuth2AuthorizationService = mock()
  private val userAuthorizationCodeRepository: UserAuthorizationCodeRepository = mock()
  private val oAuth2Authorization: OAuth2Authorization = mock()

  private lateinit var userAuthenticationService: UserAuthenticationService

  @BeforeEach
  fun setUp() {
    userAuthenticationService = UserAuthenticationService(delegateOAuth2AuthorizationService, userAuthorizationCodeRepository)
  }

  @Test
  fun shouldJustSaveWhenNotUsernamePasswordAuthenticationToken() {
    SecurityContextHolder.getContext().authentication = TestingAuthenticationToken(null, null)

    userAuthenticationService.save(oAuth2Authorization)

    verify(delegateOAuth2AuthorizationService).save(oAuth2Authorization)
    verifyNoInteractions(userAuthorizationCodeRepository)
  }

  @Test
  fun shouldCreateUserAuthorizationCodeRecordWhenUsernamePasswordAuthenticationToken() {
    val authenticatedUserDetails = AuthenticatedUserDetails(
      username = "TESTY",
      name = "Mr I Test",
      authorities = listOf(SimpleGrantedAuthority("ROLE_TESTING")),
      authSource = AuthSource.Auth.name,
      userId = "123456",
      jwtId = "789123456",
      uuid = UUID.randomUUID().toString(),
    )

    val usernamePasswordAuthenticationToken = UsernamePasswordAuthenticationToken(authenticatedUserDetails, null)
    SecurityContextHolder.getContext().authentication = usernamePasswordAuthenticationToken
    whenever(oAuth2Authorization.id).thenReturn("12345")

    userAuthenticationService.save(oAuth2Authorization)

    verify(delegateOAuth2AuthorizationService).save(oAuth2Authorization)
    val userAuthorizationCodeArgument = ArgumentCaptor.forClass(UserAuthorizationCode::class.java)
    verify(userAuthorizationCodeRepository).save(userAuthorizationCodeArgument.capture())

    assertThat(userAuthorizationCodeArgument.value.id).isEqualTo("12345")
    assertThat(userAuthorizationCodeArgument.value.username).isEqualTo(usernamePasswordAuthenticationToken.name)
    assertThat(userAuthorizationCodeArgument.value.userId).isEqualTo("123456")
    assertThat(userAuthorizationCodeArgument.value.name).isEqualTo("Mr I Test")
    assertThat(userAuthorizationCodeArgument.value.authSource).isEqualTo(AuthSource.Auth)
    assertThat(userAuthorizationCodeArgument.value.userUuid).isEqualTo(authenticatedUserDetails.uuid)
  }

  @Test
  fun shouldRemoveUserAuthorisationCodeRecordFirst() {
    whenever(oAuth2Authorization.id).thenReturn("12345")

    userAuthenticationService.remove(oAuth2Authorization)

    val inOrder = inOrder(userAuthorizationCodeRepository, delegateOAuth2AuthorizationService)
    inOrder.verify(userAuthorizationCodeRepository).deleteAllById(listOf("12345"))
    inOrder.verify(delegateOAuth2AuthorizationService).remove(oAuth2Authorization)
  }

  @Test
  fun shouldDelegateOnFindById() {
    userAuthenticationService.findById("id")

    verify(delegateOAuth2AuthorizationService).findById("id")
    verifyNoMoreInteractions(delegateOAuth2AuthorizationService)
    verifyNoInteractions(userAuthorizationCodeRepository)
  }

  @Test
  fun shouldDelegateOnFindByToken() {
    userAuthenticationService.findByToken("id", OAuth2TokenType.ACCESS_TOKEN)

    verify(delegateOAuth2AuthorizationService).findByToken("id", OAuth2TokenType.ACCESS_TOKEN)
    verifyNoMoreInteractions(delegateOAuth2AuthorizationService)
    verifyNoInteractions(userAuthorizationCodeRepository)
  }
}
