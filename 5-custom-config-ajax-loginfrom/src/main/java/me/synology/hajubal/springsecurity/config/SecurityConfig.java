package me.synology.hajubal.springsecurity.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.synology.hajubal.springsecurity.filter.AjaxLoginProcessingFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
@Slf4j
@Import(UserDetailsServiceAutoConfiguration.class) //application.yml에 있는 사용자 정보를 사용하는 InMemoryUserDetailsManager bean을 생성하기 위해
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring()
                // Spring Security should completely ignore URLs starting with /resources/
                .antMatchers("/resources/**", "/webjars/**", "/js/**");
    }

    @Autowired
    private InMemoryUserDetailsManager inMemoryUserDetailsManager;

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {

        AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
        AuthenticationManager manager = builder
                .userDetailsService(inMemoryUserDetailsManager)
                .and()
                .build();

        AjaxLoginProcessingFilter authFilter = new AjaxLoginProcessingFilter();
        authFilter.setAuthenticationManager(manager);
        authFilter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler());

        return http
                .csrf().disable()
                .authenticationManager(manager)
                .addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeRequests(auth -> {
                    auth
                            .anyRequest().authenticated();
                })
                .formLogin()
                    .loginPage("/login")
                    .permitAll()
                .and()
                .build();
    }

    @Bean
    public AjaxAuthenticationSuccessHandler ajaxAuthenticationSuccessHandler() {
        return new AjaxAuthenticationSuccessHandler();
    }

    static class AjaxAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response
                , Authentication authentication) throws IOException, ServletException {
            ObjectMapper mapper = new ObjectMapper();

            Object account = authentication.getPrincipal();

            response.setStatus(HttpStatus.OK.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);

            mapper.writeValue(response.getWriter(), account);
        }
    }
}

