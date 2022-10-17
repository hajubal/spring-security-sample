package me.synology.hajubal.springsecurity.config.version;

import me.synology.hajubal.springsecurity.config.common.FormAuthenticationDetailsSource;
import me.synology.hajubal.springsecurity.config.common.FormWebAuthenticationDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SecurityConfigV2 {

    @Autowired
    private FormAuthenticationDetailsSource formAuthenticationDetailsSource;

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
                        .authenticationDetailsSource(this.formAuthenticationDetailsSource)
                        .successHandler((request, response, authentication) -> {
                            System.out.println("authentication: " + authentication.getName());
                            response.sendRedirect("/");
                        })
                        .failureHandler((request, response, exception) -> {
                            System.out.println("exception: " + exception.getMessage());
                            response.sendRedirect("/loginPage");
                        })
                        .permitAll()
                        .and()
                        .authenticationManager(new ProviderManager(new AuthenticationProvider() {
                            @Override
                            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                                System.out.println("authentication = " + authentication);

                                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), null, null);

                                FormWebAuthenticationDetails details = (FormWebAuthenticationDetails) authentication.getDetails();

                                String secretKey = details.getSecretKey();

                                System.out.println("secretKey = " + secretKey);

                                return token;
                            }

                            @Override
                            public boolean supports(Class<?> authentication) {
                                return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
                            }
                        }))
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
                .build();
    }
}
