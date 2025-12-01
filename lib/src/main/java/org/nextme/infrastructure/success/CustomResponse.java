package org.nextme.infrastructure.success;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.Getter;

/**
 * API 공통 응답 포맷
 *
 * {
 *   "isSuccess": true/false,
 *   "code": "200",
 *   "message": "요청이 성공적으로 처리되었습니다.",
 *   "result": { ... }
 * }
 */
@Getter
@JsonPropertyOrder({"isSuccess", "code", "message", "result"})
public class CustomResponse<T> {

    @JsonProperty("isSuccess")
    private final boolean isSuccess;

    private final String code;
    private final String message;
    private final T result;

    private CustomResponse(boolean isSuccess, String code, String message, T result) {
        this.isSuccess = isSuccess;
        this.code = code;
        this.message = message;
        this.result = result;
    }

    /* ====== 성공 응답 ====== */

    // 가장 기본 성공: 200 OK + GeneralSuccessCode._OK
    public static <T> CustomResponse<T> onSuccess(T result) {
        SuccessReasonDTO dto = GeneralSuccessCode._OK.getReasonHttpStatus();
        return new CustomResponse<>(dto.getIsSuccess(), dto.getCode(), dto.getMessage(), result);
    }

    // 특정 성공 코드 사용 (예: _CREATED, _NO_CONTENT 등)
    public static <T> CustomResponse<T> of(BaseSuccessCode successCode, T result) {
        SuccessReasonDTO dto = successCode.getReasonHttpStatus();
        return new CustomResponse<>(dto.getIsSuccess(), dto.getCode(), dto.getMessage(), result);
    }

    // 메시지만 바꾸고 싶을 때 (코드는 기본 200으로)
    public static <T> CustomResponse<T> onSuccess(String message, T result) {
        SuccessReasonDTO dto = GeneralSuccessCode._OK.getReasonHttpStatus();
        return new CustomResponse<>(true, dto.getCode(), message, result);
    }

    /* ====== 실패 응답 ====== */

    // 실패: 코드/메시지 + 부가 데이터(result)에 에러 상세를 담고 싶을 때
    public static <T> CustomResponse<T> onFailure(String code, String message, T result) {
        return new CustomResponse<>(false, code, message, result);
    }

    // 실패: 코드/메시지만 넘기고, result는 null
    public static <T> CustomResponse<T> onFailure(String code, String message) {
        return new CustomResponse<>(false, code, message, null);
    }
}
