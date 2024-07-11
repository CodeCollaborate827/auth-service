package com.chat.auth_service.exception;

import com.chat.auth_service.server.model.CommonErrorResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class ApplicationExceptionHandler {
    @ExceptionHandler(ApplicationException.class)
    public ResponseEntity<CommonErrorResponse> handleException(ApplicationException ex) {
        CommonErrorResponse commonErrorResponse = new CommonErrorResponse();
        ErrorCode errorCode = ex.getErrorCode();

        commonErrorResponse.errorCode(errorCode.name());
        commonErrorResponse.setMessage(errorCode.getErrorMessage());

        return ResponseEntity.status(errorCode.getHttpStatus()).body(commonErrorResponse);
    }
}
