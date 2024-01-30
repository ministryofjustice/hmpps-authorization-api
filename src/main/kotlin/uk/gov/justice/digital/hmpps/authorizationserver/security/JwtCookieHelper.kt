package uk.gov.justice.digital.hmpps.authorizationserver.security

import org.springframework.stereotype.Component
import java.time.Duration

@Component
class JwtCookieHelper() : CookieHelper("jwtSession", Duration.ofDays(1)) // TODO parameters should be via configuration
