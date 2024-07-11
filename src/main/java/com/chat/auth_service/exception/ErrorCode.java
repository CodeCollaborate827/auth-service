package com.chat.auth_service.exception;

public enum ErrorCode {

    USER_ERROR1("User not found", 404),
    USER_ERROR2("User already exists", 409),
    USER_ERROR3("User not verified", 401),
    USER_ERROR4("Username already taken", 409),

    AUTH_ERROR1("Invalid password", 401),
    AUTH_ERROR2("", 401);

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
