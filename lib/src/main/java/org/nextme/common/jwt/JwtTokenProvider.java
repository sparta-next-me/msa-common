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

    public JwtTokenProvider(String secret,
                            long accessTokenValiditySeconds,
                            long refreshTokenValiditySeconds) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenValidity = accessTokenValiditySeconds * 1000L;
        this.refreshTokenValidity = refreshTokenValiditySeconds * 1000L;
    }

    // ================== 발급 영역 ==================

    /**
     * [기존] 유저 ID + 권한 목록으로 access/refresh 토큰 한 쌍 발급.
     *  - 하위 호환용 (name/email/slackId 없음)
     *  - 내부적으로는 신규 버전(generateTokenPair(userId, null, null, null, roles)) 호출
     */
    public JwtTokenPair generateTokenPair(String userId, List<String> roles) {
        return generateTokenPair(userId, null, null, null, roles);
    }

    /**
     * [신규] 유저 ID + name + email + slackId + 권한 목록으로 access/refresh 토큰 한 쌍 발급.
     */
    public JwtTokenPair generateTokenPair(
            String userId,
            String name,
            String email,
            String slackId,
            List<String> roles
    ) {
        String accessToken = generateAccessToken(userId, name, email, slackId, roles);
        String refreshToken = generateRefreshToken(userId, name, email, slackId, roles);
        return new JwtTokenPair(accessToken, refreshToken);
    }

    /**
     * [기존] AccessToken 발급 (userId + roles만 사용)
     *  - 내부적으로 신규 버전 호출 (name/email/slackId = null)
     */
    public String generateAccessToken(String userId, List<String> roles) {
        return generateAccessToken(userId, null, null, null, roles);
    }

    /**
     * [신규] AccessToken 발급
     * - subject : userId
     * - roles   : 권한 목록
     * - type    : "access"
     * - name    : 유저 이름
     * - email   : 이메일
     * - slackId : 슬랙 ID
     */
    public String generateAccessToken(
            String userId,
            String name,
            String email,
            String slackId,
            List<String> roles
    ) {
        long now = System.currentTimeMillis();
        Date issuedAt = new Date(now);
        Date expiry = new Date(now + accessTokenValidity);

        return Jwts.builder()
                .setSubject(userId)
                .claim("roles", roles)
                .claim("type", "access")
                .claim("name", name)
                .claim("email", email)
                .claim("slackId", slackId)
                .setIssuedAt(issuedAt)
                .setExpiration(expiry)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * [기존] RefreshToken 발급 (최소 정보만)
     *  - 내부적으로 신규 버전 호출 (name/email/slackId = null)
     */
    public String generateRefreshToken(String userId) {
        return generateRefreshToken(userId, null, null, null, List.of());
    }

    /**
     * [신규] RefreshToken 발급
     *
     * - subject : userId
     * - type    : "refresh"
     * - name/email/slackId/roles 도 함께 넣어서,
     *   재발급 API에서 DB 조회 없이 새 토큰 만들 수 있게 함.
     */
    public String generateRefreshToken(
            String userId,
            String name,
            String email,
            String slackId,
            List<String> roles
    ) {
        long now = System.currentTimeMillis();
        Date issuedAt = new Date(now);
        Date expiry = new Date(now + refreshTokenValidity);

        return Jwts.builder()
                .setSubject(userId)
                .claim("type", "refresh")
                .claim("roles", roles)
                .claim("name", name)
                .claim("email", email)
                .claim("slackId", slackId)
                .setIssuedAt(issuedAt)
                .setExpiration(expiry)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // ================== 파싱/조회 영역 ==================

    public Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public String getUserId(String token) {
        return parseClaims(token).getSubject();
    }

    public String getTokenType(String token) {
        return parseClaims(token).get("type", String.class);
    }

    @SuppressWarnings("unchecked")
    public List<String> getRoles(String token) {
        Object raw = parseClaims(token).get("roles");
        if (raw instanceof List<?> list) {
            return list.stream().map(Object::toString).toList();
        }
        return List.of();
    }

    public String getName(String token) {
        return parseClaims(token).get("name", String.class);
    }

    public String getEmail(String token) {
        return parseClaims(token).get("email", String.class);
    }

    public String getSlackId(String token) {
        return parseClaims(token).get("slackId", String.class);
    }

    /**
     * 해당 토큰이 만료될 때까지 남은 시간(ms)
     * - 블랙리스트 TTL 설정할 때 사용
     */
    public long getRemainingValidityMillis(String token) {
        Claims claims = parseClaims(token);
        Date exp = claims.getExpiration();
        long remaining = exp.getTime() - System.currentTimeMillis();
        return Math.max(remaining, 0L);
    }
}
