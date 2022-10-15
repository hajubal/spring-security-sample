package me.synology.hajubal.springsecurity.config.version;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;

public class SecurityConfigV5 {

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring()
                // Spring Security should completely ignore URLs starting with /resources/
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                ;
    }

    @Order(1)
    @Bean
    public SecurityFilterChain configure1(HttpSecurity http) throws Exception {
        return http
                .antMatcher("/user")
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .and()
                .build();
    }

    @Order(2)
    @Bean
    public SecurityFilterChain configure2(HttpSecurity http) throws Exception {
        return http
                .antMatcher("/admin")
                .authorizeRequests()
                .antMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and()
                .httpBasic()
                .and()
                .build();
    }

    @Order(3)
    @Bean
    public SecurityFilterChain configure3(HttpSecurity http) throws Exception {
        return http
                .antMatcher("/sys")
                .authorizeRequests()
                .antMatchers("/sys").hasRole("SYS")
                .anyRequest().authenticated()
                .and()
                .httpBasic()
                .and()
                .build();
    }

    @Order(99)
    @Bean
    public SecurityFilterChain configure0(HttpSecurity http) throws Exception {
        return http
                .formLogin()
                .and()
                .logout()
                .and()
                .build();
    }
}
