package org.nextme.infrastructure.exception;

import lombok.Getter;
import org.springframework.http.HttpStatusCode;
import org.springframework.web.client.HttpStatusCodeException;

@Getter
public class ApplicationException extends HttpStatusCodeException {

    private final String code;
    private final String message;

    public ApplicationException(ErrorCode errorCode) {
        super(errorCode.getHttpStatus());
        this.code = errorCode.getCode();
        this.message = errorCode.getDefaultMessage();
    }

    public ApplicationException(ErrorCode errorCode, String message) {
        super(errorCode.getHttpStatus());
        this.code = errorCode.getCode();
        this.message = message;
    }

    public ApplicationException(HttpStatusCode statusCode, String code, String message) {
        super(statusCode);
        this.code = code;
        this.message = message;
    }
}