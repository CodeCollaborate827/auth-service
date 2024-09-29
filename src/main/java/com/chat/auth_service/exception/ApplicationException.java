package com.chat.auth_service.exception;

import lombok.Getter;

@Getter
public class ApplicationException extends RuntimeException {

  private final ErrorCode errorCode;
  private final String requestId;

  public ApplicationException(ErrorCode errorCode) {
    this.errorCode = errorCode;
    this.requestId = null;
  }
  public ApplicationException(ErrorCode errorCode, String requestId) {
    this.errorCode = errorCode;
    this.requestId = requestId;
  }
}
