package uk.gov.justice.digital.hmpps.authorizationapi.data.repository

import org.springframework.data.repository.CrudRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.AuthorizationConsent

interface AuthorizationConsentRepository : CrudRepository<AuthorizationConsent, AuthorizationConsent.AuthorizationConsentId> {
  fun deleteByPrincipalName(clientId: String)
}
