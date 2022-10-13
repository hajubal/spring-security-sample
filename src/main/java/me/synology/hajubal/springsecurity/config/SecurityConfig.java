package me.synology.hajubal.springsecurity.config;

import me.synology.hajubal.springsecurity.config.version.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Import(SecurityConfigV5.class)
//@Import(SecurityConfigV4.class)
//@Import(SecurityConfigV3.class)
//@Import(SecurityConfigV2.class)
//@Import(SecurityConfigV1.class)
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("user")
                .roles("USER")
                .build();

        UserDetails sys = User.withDefaultPasswordEncoder()
                .username("sys")
                .password("sys")
                .roles("SYS")
                .build();

        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("admin")
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, sys, admin);
    }
}
