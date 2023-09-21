package uk.gov.justice.digital.hmpps.authorizationserver.data.repository

import org.springframework.data.repository.CrudRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.AuthorizationConsent

interface AuthorizationConsentRepository : CrudRepository<AuthorizationConsent, AuthorizationConsent.AuthorizationConsentId> {
  fun findByPrincipalName(principalName: String): AuthorizationConsent?
}
