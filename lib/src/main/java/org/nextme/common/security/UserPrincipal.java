package org.nextme.common.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

public record UserPrincipal(
        String userId,   // UUID 문자열
        String username, // 로그인 ID (user_name)
        String name,     // 실 이름
        String email,    // 이메일
        String slackId,  // 슬랙 ID (nullable)
        String password,
        List<String> roles,
        Collection<? extends GrantedAuthority> authorities
) implements UserDetails {

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    /** Spring Security가 쓰는 "username" (로그인 ID) */
    @Override
    public String getUsername() {
        return username;
    }

    /** 우리 서비스에서 쓸 실제 이름 */
    public String getName() {
        return name;
    }

    public String getEmail() {
        return email;
    }

    public String getSlackId() {
        return slackId;
    }

    public List<String> getRoles() {
        return roles;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
