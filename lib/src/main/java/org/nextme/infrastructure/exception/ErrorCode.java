package org.nextme.infrastructure.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    OK(HttpStatus.OK, "OK", "OK"),
    BAD_REQUEST(HttpStatus.BAD_REQUEST, "BAD_REQUEST", "Bad Request"),
    UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized"),
    FORBIDDEN(HttpStatus.FORBIDDEN, "FORBIDDEN", "Forbidden"),
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR", "Internal Server Error"),

    // validation
    REQUEST_VALIDATION_ERROR(HttpStatus.PRECONDITION_FAILED, "REQUEST_VALIDATION_ERROR", "Request value is not valid"),

    // user
    DUPLICATED_USERNAME(HttpStatus.CONFLICT, "DUPLICATED_USERNAME", "Username is already taken."),
    DUPLICATED_EMAIL(HttpStatus.CONFLICT, "DUPLICATED_EMAIL", "Email is already in use."),
    USER_NOT_FOUND(HttpStatus.NOT_FOUND,"USER_NOT_FOUND", "User Not Found"),

    // authz (권한 없음)
    ACCESS_DENIED(HttpStatus.FORBIDDEN, "ACCESS_DENIED", "Access is denied.");

    private final HttpStatus httpStatus;
    private final String code;
    private final String defaultMessage;
}
