package com.chat.auth_service.exception;

public enum ErrorCode {
  AUTH_ERROR1("User not found", 404),
  AUTH_ERROR2("User email already exists", 409),
  AUTH_ERROR3("User not verified", 401),
  AUTH_ERROR4("Username already taken", 409),

  AUTH_ERROR5("Wrong username or password", 401),
  AUTH_ERROR6("", 401),

  AUTH_ERROR7("Error when sending the email", 500),
  AUTH_ERROR8(
      "Invalid operation, valid types are ['ACCOUNT_REGISTRATION', 'FORGOT_PASSWORD']", 400),
  AUTH_ERROR9("Invalid operation, user's account was already registered and verified", 400),
  AUTH_ERROR10("Too many requests. Please try later", 400),
  AUTH_ERROR11("Cannot process email verification", 500),
  AUTH_ERROR12("Invalid verification code", 400),
  AUTH_ERROR13("Verification code expired", 400),

  AUTH_ERROR14("Invalid refresh token", 401),
  AUTH_ERROR15("Refresh token expired", 401),
  AUTH_ERROR16("Refresh token not found", 404),
  AUTH_ERROR17("Refresh token reaches limit", 400),
  AUTH_ERROR18("Refresh token only gets after 5 minutes", 400),
  AUTH_ERROR19("Reset password token not found", 404),
  AUTH_ERROR20("Reset password token invalid", 400),
  AUTH_ERROR21("Required field is missing", 400),

  MEDIA_UPLOAD_FAILED("Can not upload the image", 500);

  private final String errorMessage;
  private final int httpStatus;

  ErrorCode(String errorMessage, int httpStatus) {
    this.errorMessage = errorMessage;
    this.httpStatus = httpStatus;
  }

  public String getErrorMessage() {
    return errorMessage;
  }

  public int getHttpStatus() {
    return httpStatus;
  }
}
