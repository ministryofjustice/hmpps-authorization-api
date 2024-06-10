package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class AuthSourceTest {

  @Test
  fun shouldGetLowerCaseNameInSourceField() {
    assertThat(AuthSource.AzureAd.source).isEqualTo("azuread")
  }

  @Test
  fun shouldGetAuthSourceNoneWhenResolvingNull() {
    assertThat(AuthSource.fromNullableString(null)).isEqualTo(AuthSource.None)
  }

  @Test
  fun shouldResolveAzureAdLowerCaseToAuthSource() {
    assertThat(AuthSource.fromNullableString("azuread")).isEqualTo(AuthSource.AzureAd)
  }

  @Test
  fun shouldResolveNomisLowerCaseToAuthSource() {
    assertThat(AuthSource.fromNullableString("nomis")).isEqualTo(AuthSource.Nomis)
  }
}
