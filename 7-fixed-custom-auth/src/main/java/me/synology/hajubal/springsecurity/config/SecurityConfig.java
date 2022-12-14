package me.synology.hajubal.springsecurity.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.annotation.Jsr250SecurityConfig;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.*;

@Slf4j
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring()
                // Spring Security should completely ignore URLs starting with /resources/
                .antMatchers("/resources/**");
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
        AuthenticationManager manager = builder.userDetailsService(userDetailsService()).and().build();

        return http
                .authorizeRequests()
//                    .expressionHandler(webSecurityExpressionHandler())
                    .anyRequest().authenticated()
                .and()
                    .formLogin()
                .and()
                    .authenticationManager(manager)
                    .addFilterAt(customFilterSecurityInterceptor(manager), FilterSecurityInterceptor.class)
                .build();
    }

    public FilterSecurityInterceptor customFilterSecurityInterceptor(AuthenticationManager manager) {
        FilterSecurityInterceptor interceptor = new FilterSecurityInterceptor();
        interceptor.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());
        interceptor.setAccessDecisionManager(affirmativeBased());
        interceptor.setAuthenticationManager(manager);

        return interceptor;
    }

    private AccessDecisionManager affirmativeBased() {
        List<AccessDecisionVoter<?>> voters = new ArrayList<>();
        voters.add(roleVoter());

        return new AffirmativeBased(voters);
    }

    @Bean
    public AccessDecisionVoter<? extends Object> roleVoter() {
        RoleHierarchyVoter roleHierarchyVoter = new RoleHierarchyVoter(roleHierarchy());
        //roleHierarchyVoter.setRolePrefix("");
        return roleHierarchyVoter;
    }

    /**
     * voter??? ???????????? ????????? ?????? default??? ????????? ??? ?????? ???????????? ?????????.
     * WebSecurityConfiguration ???????????? ?????? ????????? ????????? bean??? ??????????????? ??????. ?????? @Bean?????? ???????????? ????????? spring security 5.7 ????????? ???????????? ??????.
     * 5.7 ?????? ??????????????? HttpConfigBuilder?????? expressionHander??? ???????????? ?????? ????????? ?????????. ????????? ????????? ??????.
     * TODO: ?????? ????????? ??????????????? ?????? ??????. ?????? URL: https://www.baeldung.com/role-and-privilege-for-spring-security-registration
     *
     * DefaultWebSecurityExpressionHandler ???????????? spring security?????? default??? ????????? ????????? ????????????.
     * ?????? ???: https://ncucu.me/109
     *
     * @return
     */
//    @Bean
//    public DefaultWebSecurityExpressionHandler webSecurityExpressionHandler() {
//        DefaultWebSecurityExpressionHandler expressionHandler = new DefaultWebSecurityExpressionHandler();
//        expressionHandler.setRoleHierarchy(roleHierarchy());
//        return expressionHandler;
//    }

    @Bean
    public RoleHierarchyImpl roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("""
                ROLE_ADMIN > ROLE_MANAGER
                ROLE_ADMIN > ROLE_DELETE_USER
                ROLE_ADMIN > ROLE_ADD_MANAGER
                ROLE_ADMIN > ROLE_DELETE_MANAGER
                ROLE_MANAGER > ROLE_USER
                ROLE_MANAGER > ROLE_UPDATE_USER
                ROLE_MANAGER > ROLE_ADD_USER
                ROLE_USER > ROLE_READ""");
        return roleHierarchy;
    }

    /**
     * url ?????? ?????? ??????
     *
     * @return
     */
    @Bean
    public FilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() {
        /**
         * ConfigAttribute ?????? ????????? ??????, RoleHierarchyVoter ?????? default??? ????????? ROLE_??? ????????????.
         * user builder??? ?????? user??? ????????? ????????? ?????? ???????????? ROLE_??? ?????? ????????????.
         */
        LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = new LinkedHashMap<>();

        requestMap.put(new AntPathRequestMatcher("/admin"), org.springframework.security.access.SecurityConfig.createList("ROLE_ADMIN"));
        requestMap.put(new AntPathRequestMatcher("/manager"), org.springframework.security.access.SecurityConfig.createList("ROLE_MANAGER"));

        //TODO ROLE_MANAGER ???????????? /updateUser ?????? ??? FilterSecurityInterceptor ??????????????? invoke ?????? ??? "Did not switch RunAs authentication since RunAsManager returned null" ????????? ?????? ?????? ??????
        requestMap.put(new AntPathRequestMatcher("/updateUser"), org.springframework.security.access.SecurityConfig.createList("ROLE_UPDATE_USER", "ROLE_ADMIN"));

        return new DefaultFilterInvocationSecurityMetadataSource(requestMap);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager();

        userDetailsManager.createUser(User.builder()
                .username("user")
                .password(bCryptPasswordEncoder().encode("user"))
                .roles("USER")
                .build());

        userDetailsManager.createUser(User.builder()
                .username("admin")
                .password(bCryptPasswordEncoder().encode("admin"))
                .roles("ADMIN")
                .build());

        userDetailsManager.createUser(User.builder()
                .username("admin2")
                .password(bCryptPasswordEncoder().encode("admin"))
                .roles("ADMIN")
                .build());

        userDetailsManager.createUser(User.builder()
                .username("manager")
                .password(bCryptPasswordEncoder().encode("manager"))
                .roles("MANAGER")
                .build());

        /**
         * ????????? ?????? ?????????  authorities ???????????? ?????? role??? ???????????? ???.
         * role??? ???????????? authorities ???????????? ???????????? ?????????
         *
         */
        userDetailsManager.createUser(User.builder()
                .username("manager2")
                .password(bCryptPasswordEncoder().encode("manager"))
                .roles("MANAGER")
                        .authorities("attr1", "attr2")
                .build());

        return userDetailsManager;
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
