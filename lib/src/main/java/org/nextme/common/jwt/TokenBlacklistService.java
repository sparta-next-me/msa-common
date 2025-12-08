package org.nextme.common.jwt;

public interface TokenBlacklistService {

    /**
     * 토큰을 블랙리스트에 추가
     * @param token  블랙리스트에 넣을 JWT 문자열
     * @param millis 토큰 만료까지 남은 시간(ms)
     */
    void blacklist(String token, long millis);

    /**
     * 토큰이 블랙리스트에 있는지 여부
     */
    boolean isBlacklisted(String token);
}
