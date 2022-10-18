package me.synology.hajubal.springsecurity.security.configs.version;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

public class SecurityConfigV4 {

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring()
                // Spring Security should completely ignore URLs starting with /resources/
                .antMatchers("/resources/**");
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        return http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/sys").hasAnyRole("SYS", "ADMIN")
                .antMatchers("/admin").access("hasRole('ADMIN')")
                .and()
                    .formLogin()
                        .loginPage("/loginPage")
                        .usernameParameter("userId")
                        .passwordParameter("passwd")
                        .loginProcessingUrl("/login")
                        .successHandler((request, response, authentication) -> {
                            RequestCache requestCache = new HttpSessionRequestCache();
                            SavedRequest savedRequest = requestCache.getRequest(request, response);
                            String redirectUrl = savedRequest.getRedirectUrl();
                            response.sendRedirect(redirectUrl);
                        })
                        .permitAll()
                .and()
                    .exceptionHandling()
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.sendRedirect("/loginPage");
                        })
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.sendRedirect("/denied");
                        })
                .and()
                .build();
    }
}
