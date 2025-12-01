package org.nextme.common.config;

import org.antlr.v4.runtime.misc.NotNull;
import org.nextme.common.security.UserPrincipal;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

public class AuditorAwareImpl implements AuditorAware<String> {

    @Override
    @NotNull
    public Optional<String> getCurrentAuditor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() ||
                authentication.getPrincipal().equals("anonymousUser")) {
            return Optional.empty(); // (비로그인 사용자 처리)
        }

        // [수정된 코드] UserPrincipal에서 'username' 또는 'ID'만 추출
        UserPrincipal principal = (UserPrincipal) authentication.getPrincipal();

        // principal.getUserId()가 'user01'을 반환한다고 가정
        return Optional.of(principal.userId());
    }
}