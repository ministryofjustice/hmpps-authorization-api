package uk.gov.justice.digital.hmpps.hmppsauthorizationserver.model

import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id

@Entity
data class RegisteredUser (

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  val id: Long? = null,

  val userName: String,

  val password: String,

  val role: String,
)