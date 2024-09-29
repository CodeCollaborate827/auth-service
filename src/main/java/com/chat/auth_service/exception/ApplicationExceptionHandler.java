package com.chat.auth_service.exception;

import com.chat.auth_service.server.model.CommonResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class ApplicationExceptionHandler {
  @ExceptionHandler(ApplicationException.class)
  public ResponseEntity<CommonResponse> handleException(ApplicationException ex) {
    CommonResponse commonErrorResponse = new CommonResponse();
    ErrorCode errorCode = ex.getErrorCode();

    commonErrorResponse.errorCode(errorCode.name());
    commonErrorResponse.setMessage(errorCode.getErrorMessage());
    commonErrorResponse.setRequestId(ex.getRequestId());
    return ResponseEntity.status(errorCode.getHttpStatus()).body(commonErrorResponse);
  }
}
