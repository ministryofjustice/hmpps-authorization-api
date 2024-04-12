package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.springframework.security.core.userdetails.UserDetails

class MfaClientService {

  fun clientNeedsMfa(clientId: String?, user: UserDetails?): Boolean {
    /* TODO
    1. Load client details by client id
    2. Return false if MFA not set to all
    3. If MFA is set to all and client not configured for remember me return true
    4. If MFA is set to all and client is configured for remember me return false if remember me token valid, true otherwise
     */

    return false
  }
}
