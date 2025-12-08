package org.nextme.common.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.nextme.common.jwt.JwtTokenProvider;
import org.nextme.common.jwt.TokenBlacklistService;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 *   Gateway 없이 각 마이크로서비스에 직접 요청할 때 사용하는 공통 JWT 필터
 *
 * - 이미 SecurityContext에 인증이 있으면 아무 것도 안 함 (Gateway가 인증해줬다는 뜻)
 * - Authorization: Bearer 토큰이 없으면 패스
 * - 토큰이 있으면:
 *      - 유효성 검사 + 블랙리스트 확인 + type=access 확인
 *      - userId, roles 꺼내서 UserPrincipal 생성
 *      - SecurityContext 에 Authentication 세팅
 *
 *   ignorePathPrefixes 에 포함된 경로들은 이 필터가 아예 동작하지 않음 (shouldNotFilter)
 */
@RequiredArgsConstructor
public class DirectJwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final TokenBlacklistService tokenBlacklistService;

    // 이 경로들로 시작하는 URI는 필터 완전 제외 (각 서비스에서 생성 시 주입)
    private final List<String> ignorePathPrefixes;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if (ignorePathPrefixes == null || ignorePathPrefixes.isEmpty()) {
            return false;
        }

        String uri = request.getRequestURI();
        return ignorePathPrefixes.stream().anyMatch(uri::startsWith);
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        // 1. 이미 인증이 있으면 건드리지 않음 (Gateway 경유 케이스 등)
        Authentication existing = SecurityContextHolder.getContext().getAuthentication();
        if (existing != null && existing.isAuthenticated()) {
            filterChain.doFilter(request, response);
            return;
        }

        // 2. Authorization 헤더에서 Bearer 토큰 추출
        String bearer = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (!StringUtils.hasText(bearer) || !bearer.startsWith("Bearer ")) {
            // 토큰 없으면 그냥 다음 필터로
            filterChain.doFilter(request, response);
            return;
        }

        String token = bearer.substring(7);

        // 3. 토큰 유효성 검사
        if (!jwtTokenProvider.validateToken(token)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // 3-1. 블랙리스트 확인
        if (tokenBlacklistService.isBlacklisted(token)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // 4. access 토큰인지 확인
        String tokenType = jwtTokenProvider.getTokenType(token);
        if (!"access".equals(tokenType)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // 5. userId, roles 추출
        String userId  = jwtTokenProvider.getUserId(token);
        List<String> roles = jwtTokenProvider.getRoles(token);
        String name    = jwtTokenProvider.getName(token);
        String email   = jwtTokenProvider.getEmail(token);
        String slackId = jwtTokenProvider.getSlackId(token);

        List<SimpleGrantedAuthority> authorities = roles.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .map(role -> "ROLE_" + role)
                .map(SimpleGrantedAuthority::new)
                .toList();

        UserPrincipal principal = new UserPrincipal(
                userId,         // userId
                userId,         // username
                name,
                email,
                slackId,
                null,           // password (JWT 기반이라 비밀번호는 안 씀)
                authorities
        );

        Authentication authentication =
                new UsernamePasswordAuthenticationToken(principal, null, authorities);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 6. 다음 필터로 진행
        filterChain.doFilter(request, response);
    }
}
