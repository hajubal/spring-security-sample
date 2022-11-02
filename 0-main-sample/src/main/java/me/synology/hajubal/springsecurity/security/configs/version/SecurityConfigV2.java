package me.synology.hajubal.springsecurity.security.configs.version;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SecurityConfigV2 {


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
                        .antMatchers("/login*").permitAll()
                    .and()
                    .formLogin()
                        /*
                         * loginPage를 지정하면 spring에서 기본으로 제공되는 페이지와 동일한 url 이라도 default page는 작동하지 않음.
                         * login page html을 작성하지 않고 loginPage 설정하면 404에러가 발생
                         * loginProcessingUrl도 지정하지 않으면 기본 /login servlet이 동작하지 않는다.
                         */
                        .loginPage("/loginPage")
                        .loginProcessingUrl("/login")
                        .defaultSuccessUrl("/")
                        .failureUrl("/loginPage")
                        .usernameParameter("userId")
                        .passwordParameter("passwd")
                        .permitAll()
                        .and()
                    .logout()
                        .logoutUrl("/logout")
                        .logoutSuccessHandler(new LogoutSuccessHandler() {
                            @Override
                            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

                            }
                        })
                .and()
                    .authorizeRequests()
                    .anyRequest().authenticated()
                .and()
                .exceptionHandling()
                .and()
                .build();
    }
}
