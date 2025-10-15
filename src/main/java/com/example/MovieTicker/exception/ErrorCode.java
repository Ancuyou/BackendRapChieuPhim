package com.example.MovieTicker.exception;

import org.springframework.http.HttpStatus;

import lombok.Getter;
@Getter
public enum ErrorCode {
    INVALID_KEY(1001, "Invalid Key", HttpStatus.BAD_REQUEST),
    USER_EXISTS(1002, "User exists", HttpStatus.BAD_REQUEST),
    UNCATEGORIZED_EXCEPTION(9999, "Uncategorized exception", HttpStatus.INTERNAL_SERVER_ERROR),
    USERNAME_INVALID(1003,"Username must be at {min} characters", HttpStatus.BAD_REQUEST),
    PASSWORD_INVALID(1004, "Password must be at least {min} characters", HttpStatus.BAD_REQUEST),
    INVALID_REQUEST(2002, "Invalid request", HttpStatus.BAD_REQUEST),
    USER_NOT_FOUND(1005, "User not found", HttpStatus.NOT_FOUND),
    UNTHENTICATED(1006, "User is not authenticated", HttpStatus.UNAUTHORIZED),
    UNAUTHORIZED(1007, "User do not have permisson", HttpStatus.FORBIDDEN),
    PERMISSION_ALREADY_EXISTS(1008, "Permission already exists", HttpStatus.BAD_REQUEST),
    ROLE_ALREADY_EXISTS(1009, "Role already exists", HttpStatus.BAD_REQUEST),
    ROLE_NOT_FOUND(1010, "Role not found", HttpStatus.NOT_FOUND),
    EMAIL_EXISTS(1011, "Email already exists", HttpStatus.BAD_REQUEST),
    PERMISSION_NOT_FOUND(1011, "Permission not found", HttpStatus.NOT_FOUND),
    DOB_INVALID(1012, "User must be at least {min} years old", HttpStatus.BAD_REQUEST),
    INTERNAL_SERVER_ERROR(2003, "Internal server error", HttpStatus.INTERNAL_SERVER_ERROR),
    INVALID_TOKEN(1013, "Invalid token", HttpStatus.BAD_REQUEST),
    TOKEN_EXPIRED(1014, "Token has expired", HttpStatus.BAD_REQUEST);

    private int code;
    private String message;
    private HttpStatus status;

    ErrorCode(int code, String message, HttpStatus status) {
        this.code = code;
        this.message = message;
        this.status = status;
    }
}
