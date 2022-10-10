package me.synology.hajubal.springsecurity.config.version;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public class SecurityConfigV1 {

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        return http
                .build();
    }
}
