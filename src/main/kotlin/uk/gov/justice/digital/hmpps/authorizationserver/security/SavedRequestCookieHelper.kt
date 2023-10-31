package uk.gov.justice.digital.hmpps.authorizationserver.security

import org.springframework.stereotype.Component
import java.time.Duration

@Component
class SavedRequestCookieHelper() : CookieHelper("savedrequest", Duration.ofDays(0)) // TODO parameters should be via configuration
