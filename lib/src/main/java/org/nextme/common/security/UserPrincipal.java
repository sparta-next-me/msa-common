package org.nextme.common.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

public record UserPrincipal(
        String userId,
        String username,
        String password,
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

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // 실제 정책에 맞게 변경 가능
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // 실제 정책에 맞게 변경 가능
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // 실제 정책에 맞게 변경 가능
    }

    @Override
    public boolean isEnabled() {
        return true; // 실제 정책에 맞게 변경 가능
    }
}