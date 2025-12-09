// msa-common
package org.nextme.common.jwt.config;

import lombok.RequiredArgsConstructor;
import org.nextme.common.jwt.JwtTokenProvider;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(JwtProperties.class)
@RequiredArgsConstructor
public class JwtAutoConfiguration {

    private final JwtProperties props;

    @Bean
    public JwtTokenProvider jwtTokenProvider() {
        return new JwtTokenProvider(
                props.getSecret(),
                props.getAccessTokenValiditySeconds(),
                props.getRefreshTokenValiditySeconds()
        );
    }
}
