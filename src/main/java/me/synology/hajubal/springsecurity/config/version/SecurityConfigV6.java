package me.synology.hajubal.springsecurity.config.version;

import me.synology.hajubal.springsecurity.config.common.FormAuthenticationDetailsSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;

public class SecurityConfigV6 {

    @Autowired
    private FormAuthenticationDetailsSource formAuthenticationDetailsSource;


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
                .authenticationManager(new ProviderManager(new AuthenticationProvider() {
                    @Override
                    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                        System.out.println("authentication = " + authentication);

                        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), null, null);

                        return token;
                    }

                    @Override
                    public boolean supports(Class<?> authentication) {
                        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
                    }
                }))
/*
                .authenticationProvider(new AuthenticationProvider() {
                    @Override
                    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                        System.out.println("authentication = " + authentication);

                        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), null, null);

                        return token;
                    }

                    @Override
                    public boolean supports(Class<?> authentication) {
                        return true;
                    }
                })
*/
                .build();
    }
}
