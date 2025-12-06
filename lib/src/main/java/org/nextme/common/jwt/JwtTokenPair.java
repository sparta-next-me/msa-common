package org.nextme.common.jwt;

/**
 * AccessToken / RefreshToken 한 쌍을 표현하는 DTO.
 * - 로그인, 토큰 재발급 응답 등에서 재사용 가능.
 */
public record JwtTokenPair(
        String accessToken,
        String refreshToken
) {
}