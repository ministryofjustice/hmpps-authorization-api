package uk.gov.justice.digital.hmpps.authorizationserver.config

import com.fasterxml.jackson.annotation.JsonInclude
import org.slf4j.LoggerFactory
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.http.HttpStatus
import org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.security.access.AccessDeniedException
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientAlreadyExistsException
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientDeploymentAlreadyExistsException
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientNotFoundException
import uk.gov.justice.digital.hmpps.authorizationserver.service.MaxDuplicateClientsException

@RestControllerAdvice
@Order(Ordered.LOWEST_PRECEDENCE)
class AuthorizationServerExceptionHandler {

  @ExceptionHandler(MaxDuplicateClientsException::class)
  fun handleDuplicateClientsException(e: MaxDuplicateClientsException): ResponseEntity<ErrorResponse> {
    log.debug("Maximum duplicate clients exception caught: {}", e.message)
    return ResponseEntity
      .status(HttpStatus.CONFLICT)
      .body(
        ErrorResponse(
          status = HttpStatus.CONFLICT,
          userMessage = e.message,
          developerMessage = e.message,
        ),
      )
  }

  @ExceptionHandler(ClientAlreadyExistsException::class)
  fun handleClientAlreadyExistsException(e: ClientAlreadyExistsException): ResponseEntity<ErrorResponse> {
    log.debug("Bad request returned with message {}", e.message)
    return ResponseEntity
      .status(HttpStatus.BAD_REQUEST)
      .contentType(MediaType.APPLICATION_JSON)
      .body(
        ErrorResponse(
          status = HttpStatus.BAD_REQUEST,
          userMessage = e.message,
          developerMessage = e.message,
        ),
      )
  }

  @ExceptionHandler(ClientDeploymentAlreadyExistsException::class)
  fun handleClientDeploymentAlreadyExistsException(e: ClientDeploymentAlreadyExistsException): ResponseEntity<ErrorResponse> {
    log.debug("Bad request returned with message {}", e.message)
    return ResponseEntity
      .status(HttpStatus.BAD_REQUEST)
      .contentType(MediaType.APPLICATION_JSON)
      .body(
        ErrorResponse(
          status = HttpStatus.BAD_REQUEST,
          userMessage = e.message,
          developerMessage = e.message,
        ),
      )
  }

  @ExceptionHandler(ClientNotFoundException::class)
  fun handleClientNotFoundException(e: ClientNotFoundException): ResponseEntity<ErrorResponse> {
    log.debug("Not found returned with message {}", e.message)
    return ResponseEntity
      .status(HttpStatus.NOT_FOUND)
      .contentType(MediaType.APPLICATION_JSON)
      .body(
        ErrorResponse(
          status = HttpStatus.NOT_FOUND,
          userMessage = e.message,
          developerMessage = e.message,
        ),
      )
  }

  @ExceptionHandler(AccessDeniedException::class)
  fun handleAccessDeniedException(e: AccessDeniedException): ResponseEntity<ErrorResponse> {
    log.debug("Forbidden (403) returned with message {}", e.message)
    return ResponseEntity
      .status(HttpStatus.FORBIDDEN)
      .contentType(MediaType.APPLICATION_JSON)
      .body(
        ErrorResponse(
          status = HttpStatus.FORBIDDEN,
          userMessage = e.message,
          developerMessage = e.message,
        ),
      )
  }

  @ExceptionHandler(java.lang.Exception::class)
  fun handleException(e: java.lang.Exception): ResponseEntity<ErrorResponse?>? {
    log.error("Unexpected exception", e)
    return ResponseEntity
      .status(INTERNAL_SERVER_ERROR)
      .body(
        ErrorResponse(
          status = INTERNAL_SERVER_ERROR,
          userMessage = "Unexpected error: ${e.message}",
          developerMessage = e.message,
        ),
      )
  }

  @ExceptionHandler(MethodArgumentNotValidException::class)
  fun handleMethodArgumentNotValidException(e: MethodArgumentNotValidException): ResponseEntity<ErrorResponse?>? {
    log.info("Validation exception: {}", e.message)
    return ResponseEntity
      .status(HttpStatus.BAD_REQUEST)
      .contentType(MediaType.APPLICATION_JSON)
      .body(
        ErrorResponse(
          status = HttpStatus.BAD_REQUEST,
          userMessage = e.message,
          developerMessage = e.message,
          errors = e.asErrorList(),
        ),
      )
  }

  private fun MethodArgumentNotValidException.asErrorList(): List<String> =
    this.allErrors.mapNotNull { it.defaultMessage }

  companion object {
    private val log = LoggerFactory.getLogger(this::class.java)
  }
}

@JsonInclude(JsonInclude.Include.NON_NULL)
data class ErrorResponse(
  val status: Int,
  val errorCode: Int? = null,
  val userMessage: String? = null,
  val developerMessage: String? = null,
  val errors: List<String>? = null,
) {
  constructor(
    status: HttpStatus,
    errorCode: Int? = null,
    userMessage: String? = null,
    developerMessage: String? = null,
    errors: List<String>? = null,
  ) :
    this(status.value(), errorCode, userMessage, developerMessage, errors)
}
