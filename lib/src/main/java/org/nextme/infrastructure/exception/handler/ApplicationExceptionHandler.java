package org.nextme.infrastructure.exception.handler;

import lombok.extern.slf4j.Slf4j;
import org.nextme.infrastructure.exception.ApplicationException;
import org.nextme.infrastructure.exception.ErrorCode;
import org.nextme.infrastructure.exception.ErrorResponse;
import org.nextme.infrastructure.exception.FieldError;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@RestControllerAdvice
public class ApplicationExceptionHandler {

    @ExceptionHandler(value = ApplicationException.class)
    public ResponseEntity<ErrorResponse<Void>> handleApplicationException(ApplicationException e) {
        log.error("ApplicationException", e);

        return ResponseEntity
                .status(e.getStatusCode())
                .body(
                        new ErrorResponse<>(e.getCode(), e.getMessage(), null)
                );
    }

    @ExceptionHandler(value = MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse<List<FieldError>>> handleMethodArgumentNotValidException(MethodArgumentNotValidException e) {
        List<FieldError> fieldErrors = e.getBindingResult().getFieldErrors()
                .stream().map(
                        it -> new FieldError(it.getField(), it.getRejectedValue(), it.getDefaultMessage())
                ).toList();

        List<FieldError> globalErrors = e.getBindingResult().getGlobalErrors()
                .stream().map(
                        it -> new FieldError("global", null, it.getDefaultMessage())
                ).toList();

        List<FieldError> allErrors = new ArrayList<>();
        allErrors.addAll(fieldErrors);
        allErrors.addAll(globalErrors);

        ErrorCode errorCode = ErrorCode.REQUEST_VALIDATION_ERROR;
        return ResponseEntity
                .status(errorCode.getHttpStatus())
                .body(new ErrorResponse<>(errorCode.getCode(), errorCode.getDefaultMessage(), allErrors));
    }

    @ExceptionHandler(value = Exception.class)
    public ResponseEntity<ErrorResponse<Void>> handleAllUncaughtException(Exception e) {
        log.error("Exception", e);

        ErrorCode internalServerError = ErrorCode.INTERNAL_SERVER_ERROR;
        return ResponseEntity
                .status(internalServerError.getHttpStatus())
                .body(
                        new ErrorResponse<>(internalServerError.getCode(), internalServerError.getDefaultMessage(), null));
    }

    /**
     * 권한 없는 경우(@PreAuthorize 등에서 막힌 경우) 403으로 내려주기
     */
    @ExceptionHandler(value = AuthorizationDeniedException.class)
    public ResponseEntity<ErrorResponse<Void>> handleAuthorizationDeniedException(AuthorizationDeniedException e) {
        log.warn("AuthorizationDeniedException", e);

        // 1) infra ErrorCode 에 ACCESS_DENIED 가 이미 있다면 이렇게:
        ErrorCode errorCode = ErrorCode.ACCESS_DENIED;

        return ResponseEntity
                .status(errorCode.getHttpStatus()) // 보통 403
                .body(new ErrorResponse<>(
                        errorCode.getCode(),
                        errorCode.getDefaultMessage(),
                        null
                ));
    }
}