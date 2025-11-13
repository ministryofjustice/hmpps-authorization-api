package uk.gov.justice.digital.hmpps.authorizationapi.resource

data class ClientDeploymentViewResponse(
  val deployment: ClientDeploymentDetails?,
)

data class ClientDeploymentDetails(
  val clientType: String?,
  val team: String?,
  val teamContact: String?,
  val teamSlack: String?,
  val hosting: String?,
  val namespace: String?,
  val deployment: String?,
  val secretName: String?,
  val clientIdKey: String?,
  val secretKey: String?,
  val deploymentInfo: String?,
)
