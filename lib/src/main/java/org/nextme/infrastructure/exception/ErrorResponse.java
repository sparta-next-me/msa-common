package org.nextme.infrastructure.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class ErrorResponse<T> {

    private String code;
    private String message;
    private T details;

}