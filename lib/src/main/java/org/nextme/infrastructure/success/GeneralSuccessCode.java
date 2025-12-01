package org.nextme.infrastructure.success;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public enum GeneralSuccessCode implements BaseSuccessCode {

    _OK(HttpStatus.OK, "200", "요청이 성공적으로 처리되었습니다."),
    _CREATED(HttpStatus.CREATED, "201", "새로운 리소스가 생성되었습니다."),
    _NO_CONTENT(HttpStatus.NO_CONTENT, "204", "삭제되었습니다.");

    private final HttpStatus httpStatus;
    private final String code;
    private final String message;


    @Override
    public SuccessReasonDTO getReasonHttpStatus() {

        return SuccessReasonDTO.builder()
                .httpStatus(this.httpStatus)
                .isSuccess(true)
                .code(this.code)
                .message(this.message)
                .build();
    }
}