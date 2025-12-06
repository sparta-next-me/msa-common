package org.nextme.common.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

/**
 * JWT 발급/검증 공통 유틸.
 *
 * - 어떤 서비스에서도 사용할 수 있도록 userId는 단순 String으로만 취급한다.
 * - secret, access/refresh 만료 시간은 생성자에서 주입받는다.
 */
public class JwtTokenProvider {

    private final SecretKey key;            // HMAC 서명용 비밀 키
    private final long accessTokenValidity; // access 토큰 유효 시간(ms)
    private final long refreshTokenValidity;// refresh 토큰 유효 시간(ms)

    /**
     * @param secret                      HS256 서명에 사용할 비밀 문자열
     * @param accessTokenValiditySeconds  access 토큰 유효 기간(초)
     * @param refreshTokenValiditySeconds refresh 토큰 유효 기간(초)
     */
    public JwtTokenProvider(String secret,
                            long accessTokenValiditySeconds,
                            long refreshTokenValiditySeconds) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenValidity = accessTokenValiditySeconds * 1000L;
        this.refreshTokenValidity = refreshTokenValiditySeconds * 1000L;
    }

    // ================== 발급 영역 ==================

    /**
     * 유저 ID + 권한 목록으로 access/refresh 토큰 한 쌍을 발급.
     */
    public JwtTokenPair generateTokenPair(String userId, List<String> roles) {
        String accessToken = generateAccessToken(userId, roles);
        String refreshToken = generateRefreshToken(userId);
        return new JwtTokenPair(accessToken, refreshToken);
    }

    /**
     * AccessToken 발급
     * - subject : userId
     * - roles   : 권한 목록
     * - type    : "access"
     */
    public String generateAccessToken(String userId, List<String> roles) {
        long now = System.currentTimeMillis();
        Date issuedAt = new Date(now);
        Date expiry = new Date(now + accessTokenValidity);

        return Jwts.builder()
                .setSubject(userId)
                .claim("roles", roles)
                .claim("type", "access")
                .setIssuedAt(issuedAt)
                .setExpiration(expiry)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * RefreshToken 발급
     * - subject : userId
     * - type    : "refresh"
     */
    public String generateRefreshToken(String userId) {
        long now = System.currentTimeMillis();
        Date issuedAt = new Date(now);
        Date expiry = new Date(now + refreshTokenValidity);

        return Jwts.builder()
                .setSubject(userId)
                .claim("type", "refresh")
                .setIssuedAt(issuedAt)
                .setExpiration(expiry)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // ================== 파싱/조회 영역 ==================

    /**
     * 문자열 JWT를 파싱해서 Claims(페이로드)를 꺼낸다.
     * - 서명 검증, 만료 검증까지 같이 수행
     */
    public Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * 토큰이 유효한지 간단히 boolean으로 반환.
     */
    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * subject(userId) 꺼내기.
     */
    public String getUserId(String token) {
        return parseClaims(token).getSubject();
    }

    /**
     * type(access/refresh) 꺼내기.
     */
    public String getTokenType(String token) {
        return parseClaims(token).get("type", String.class);
    }

    /**
     * roles 클레임 꺼내기.
     */
    @SuppressWarnings("unchecked")
    public List<String> getRoles(String token) {
        Object raw = parseClaims(token).get("roles");
        if (raw instanceof List<?> list) {
            return list.stream().map(Object::toString).toList();
        }
        return List.of();
    }
}
