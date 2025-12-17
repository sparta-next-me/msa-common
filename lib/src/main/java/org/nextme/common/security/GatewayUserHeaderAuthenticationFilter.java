package org.nextme.common.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Gateway가 전달한 X-User-Id / X-User-Roles 헤더를 읽어서
 * SecurityContext에 UserPrincipal을 세팅하는 공통 필터.
 *
 * - 헤더가 없으면: 인증 없이 통과 (익명 요청)
 * - 헤더가 있으면: UserPrincipal + Authentication 생성
 */
public class GatewayUserHeaderAuthenticationFilter extends OncePerRequestFilter {

    public static final String HEADER_USER_ID = "X-User-Id";
    public static final String HEADER_USER_ROLES = "X-User-Roles";
    public static final String HEADER_USER_NAME  = "X-User-Name";   // 로그인 ID (user_name)
    public static final String HEADER_NAME       = "X-Name";        // 실제 이름
    public static final String HEADER_EMAIL      = "X-Email";
    public static final String HEADER_SLACK_ID   = "X-Slack-Id";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {


        // 이미 인증돼 있으면 건드리지 않음
        Authentication existing = SecurityContextHolder.getContext().getAuthentication();
        if (existing != null && existing.isAuthenticated()) {
            filterChain.doFilter(request, response);
            return;
        }

        String userId = request.getHeader(HEADER_USER_ID);
        String rolesHeader = request.getHeader(HEADER_USER_ROLES);

        if (!StringUtils.hasText(userId)) {
            // 게이트웨이에서 헤더 안 붙인 요청 → 익명
            filterChain.doFilter(request, response);
            return;
        }

        String userName = request.getHeader(HEADER_USER_NAME);
        String name     = request.getHeader(HEADER_NAME);
        String email    = request.getHeader(HEADER_EMAIL);
        String slackId  = request.getHeader(HEADER_SLACK_ID);
        List<String> roles = List.of();
        List<SimpleGrantedAuthority> authorities = List.of();

        if (StringUtils.hasText(rolesHeader)) {
            roles = Arrays.stream(rolesHeader.split(","))
                    .map(String::trim)
                    .filter(StringUtils::hasText)
                    .toList();

            authorities = Arrays.stream(rolesHeader.split(","))
                    .filter(StringUtils::hasText)
                    .map(String::trim)
                    .map(role -> "ROLE_" + role)
                    .map(SimpleGrantedAuthority::new)
                    .toList();
        }

        UserPrincipal principal = new UserPrincipal(
                userId,
                userName != null ? userName : userId, // 로그인 ID 없으면 일단 userId로
                name,
                email,
                slackId,
                null,           // password는 헤더로 안 내려주므로 null
                roles,
                authorities
        );

        Authentication authentication =
                new UsernamePasswordAuthenticationToken(principal, null, authorities);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request, response);
    }
}
