package me.synology.hajubal.springsecurity.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.synology.hajubal.springsecurity.common.CustomWebAuthenticationDetails;
import me.synology.hajubal.springsecurity.common.CustomWebAuthenticationDetailsSource;
import me.synology.hajubal.springsecurity.provider.CustomAuthenticationProvider;
import me.synology.hajubal.springsecurity.service.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@RequiredArgsConstructor
@Slf4j
@EnableWebSecurity
public class SecurityConfig {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    private final CustomWebAuthenticationDetailsSource customWebAuthenticationDetailsSource;

    private final UserService userService;

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring()
                // Spring Security should completely ignore URLs starting with /resources/
                .antMatchers("/resources/**", "/webjars/**");
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        return http
                //.csrf().disable()
                    .headers().frameOptions().sameOrigin()
                .and()
                .authorizeRequests(auth -> {
                    auth
                            .antMatchers("/h2-console/**").permitAll()
                            .anyRequest().authenticated();
                })
                .formLogin()
                    .loginPage("/login")
                    .loginProcessingUrl("/login_proc")
                    .authenticationDetailsSource(customWebAuthenticationDetailsSource)
                    .permitAll()
                .and()
                //.authenticationProvider(new CustomAuthenticationProvider(bCryptPasswordEncoder, userService))
                .build();
    }

//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails userDetails = User.builder()
//                .username("user")
//                .password(bCryptPasswordEncoder.encode("user"))
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(userDetails);
//    }
}
