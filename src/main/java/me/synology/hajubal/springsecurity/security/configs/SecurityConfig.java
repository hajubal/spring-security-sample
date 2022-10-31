package me.synology.hajubal.springsecurity.security.configs;

import lombok.extern.slf4j.Slf4j;
import me.synology.hajubal.springsecurity.security.common.FormWebAuthenticationDetailsSource;
import me.synology.hajubal.springsecurity.security.factory.UrlResourcesMapFactoryBean;
import me.synology.hajubal.springsecurity.security.filter.AjaxLoginProcessingFilter;
import me.synology.hajubal.springsecurity.security.filter.PermitAllFilter;
import me.synology.hajubal.springsecurity.security.handler.AjaxAuthenticationFailureHandler;
import me.synology.hajubal.springsecurity.security.handler.AjaxAuthenticationSuccessHandler;
import me.synology.hajubal.springsecurity.security.handler.FormAccessDeniedHandler;
import me.synology.hajubal.springsecurity.security.metadatasource.UrlFilterInvocationSecurityMetadatsSource;
import me.synology.hajubal.springsecurity.security.metadatasource.UrlSecurityMetadataSource;
import me.synology.hajubal.springsecurity.security.provider.AjaxAuthenticationProvider;
import me.synology.hajubal.springsecurity.security.provider.FormAuthenticationProvider;
import me.synology.hajubal.springsecurity.service.SecurityResourceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig {

    @Autowired
    private FormWebAuthenticationDetailsSource formWebAuthenticationDetailsSource;
    @Autowired
    private AuthenticationSuccessHandler formAuthenticationSuccessHandler;
    @Autowired
    private AuthenticationFailureHandler formAuthenticationFailureHandler;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private SecurityResourceService securityResourceService;

    private String[] permitAllPattern = {"/", "/home", "/users", "/login"};

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring()
                // Spring Security should completely ignore URLs starting with /resources/
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                ;
    }

    @Order(1)
    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        return http
                .csrf().disable()
                .headers().frameOptions().sameOrigin()
                .and()
                    .authorizeRequests()
                    .antMatchers("/h2-console/**").permitAll()
                    .antMatchers("/mypage").hasRole("USER")
                    .antMatchers("/messages").hasRole("MANAGER")
                    .antMatchers("/config").hasRole("ADMIN")
                    .antMatchers("/admin/**").hasRole("ADMIN")
                    .antMatchers("/**").permitAll()
                    .anyRequest().authenticated()
                .and()
                    .formLogin()
                    .loginPage("/login")
                    .loginProcessingUrl("/login_proc")
                    .authenticationDetailsSource(formWebAuthenticationDetailsSource)
                    .successHandler(formAuthenticationSuccessHandler)
                    .failureHandler(formAuthenticationFailureHandler)
                    .permitAll()
                .and()
                    .exceptionHandling()
    //                .authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint())
                    .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                    .accessDeniedPage("/denied")
                    .accessDeniedHandler(accessDeniedHandler())
//        .and()
//                .addFilterBefore(customFilterSecurityInterceptor(), FilterSecurityInterceptor.class)
                .and()
                .build();
    }


    /**
     * Custom Configurer 사용으로 ajax login 구현
     *
     * @param http
     * @return
     * @throws Exception
     */
//    @Order(0)
//    @Bean
    public SecurityFilterChain customConfigurer(HttpSecurity http) throws Exception {
        return http
                .csrf().disable()
                .antMatcher("/ajaxLogin")
                .apply(new AjaxLoginConfigurer<>())
                    .successHandlerAjax(ajaxAuthenticationSuccessHandler())
                    .failureHandlerAjax(ajaxAuthenticationFailureHandler())
                .and()
                    .authenticationProvider(authenticationProvider())
                    .authenticationProvider(ajaxAuthenticationProvider())
                .build();
    }

    /**
     * 그냥 filter로 구현
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Order(0)
    @Bean
    public SecurityFilterChain ajaxFilterChain(HttpSecurity http) throws Exception {

        /**
         * AuthenticationManager
         */
        AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
        builder.userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder());

        AuthenticationManager authenticationManager = builder.build();

        AjaxLoginProcessingFilter authFilter = new AjaxLoginProcessingFilter();
        authFilter.setAuthenticationManager(authenticationManager);
        authFilter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler());

        return http
                .csrf().disable()
                .antMatcher("/ajaxLogin")
                .authenticationManager(authenticationManager)
                .addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class)
                .authenticationProvider(ajaxAuthenticationProvider())
                    .sessionManagement()
                    .sessionFixation()
                    .changeSessionId()
                .and()
                .formLogin()
                    .loginPage("/login")
                .and()
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider(){
        return new FormAuthenticationProvider(passwordEncoder());
    }

    @Bean
    public AuthenticationProvider ajaxAuthenticationProvider(){
        return new AjaxAuthenticationProvider(passwordEncoder());
    }

    @Bean
    public AjaxAuthenticationSuccessHandler ajaxAuthenticationSuccessHandler(){
        return new AjaxAuthenticationSuccessHandler();
    }

    @Bean
    public AjaxAuthenticationFailureHandler ajaxAuthenticationFailureHandler(){
        return new AjaxAuthenticationFailureHandler();
    }

    public AccessDeniedHandler accessDeniedHandler() {
        FormAccessDeniedHandler commonAccessDeniedHandler = new FormAccessDeniedHandler();
        commonAccessDeniedHandler.setErrorPage("/denied");
        return commonAccessDeniedHandler;
    }

    @Bean
    public PermitAllFilter permitAllFilter() {
        PermitAllFilter permitAllFilter = new PermitAllFilter(permitAllPattern);
        permitAllFilter.setAccessDecisionManager(affirmativeBased());
        permitAllFilter.setSecurityMetadataSource(urlSecurityMetadataSource());
        return permitAllFilter;
    }

    @Bean
    public UrlSecurityMetadataSource urlSecurityMetadataSource() {
        return new UrlSecurityMetadataSource(urlResourcesMapFactoryBean().getObject(), securityResourceService);
    }

    @Bean
    public UrlResourcesMapFactoryBean urlResourcesMapFactoryBean(){
        UrlResourcesMapFactoryBean urlResourcesMapFactoryBean = new UrlResourcesMapFactoryBean();
        urlResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);
        return urlResourcesMapFactoryBean;
    }

//    @Bean
//    public FilterSecurityInterceptor customFilterSecurityInterceptor() throws Exception {
//
//        FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
//        filterSecurityInterceptor.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());
//        filterSecurityInterceptor.setAccessDecisionManager(affirmativeBased());
//        filterSecurityInterceptor.setAuthenticationManager(authenticationManagerBean());
//        return filterSecurityInterceptor;
//    }

    private AccessDecisionManager affirmativeBased() {
        AffirmativeBased affirmativeBased = new AffirmativeBased(getAccessDecistionVoters());
        return affirmativeBased;
    }

    private List<AccessDecisionVoter<?>> getAccessDecistionVoters() {
        return Arrays.asList(new RoleVoter());
    }

    @Bean
    public FilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() {
        return new UrlFilterInvocationSecurityMetadatsSource();
    }
}
