package uk.gov.justice.digital.hmpps.authorizationapi.data.model

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.Id
import jakarta.persistence.Table

@Entity
@Table(name = "oauth2_client_deployment_details")
data class ClientDeployment(
  @Id
  @Column(name = "base_client_id", nullable = false)
  val baseClientId: String,

  @Enumerated(EnumType.STRING)
  @Column(name = "client_type")
  var clientType: ClientType?,

  var team: String?,

  @Column(name = "team_contact")
  var teamContact: String?,

  @Column(name = "team_slack")
  var teamSlack: String?,

  @Enumerated(EnumType.STRING)
  var hosting: Hosting?,
  var namespace: String?,
  var deployment: String?,

  @Column(name = "secret_name")
  var secretName: String?,

  @Column(name = "client_id_key")
  var clientIdKey: String?,

  @Column(name = "secret_key")
  var secretKey: String?,

  @Column(name = "deployment_info")
  var deploymentInfo: String?,
)

enum class Hosting(val description: String) {
  CLOUDPLATFORM("Cloud Platform"),
  OTHER("Other"),
}

enum class ClientType(val description: String) {
  PERSONAL("Personal token"),
  SERVICE("Service token"),
}
