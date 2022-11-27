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
     * voter를 사용하는 방식이 아닌 default로 설정할 수 있는 로직으로 추정됨.
     * WebSecurityConfiguration 클래스에 이미 동일한 이름의 bean이 생성코드가 있음. 아래 @Bean으로 등록하는 방식은 spring security 5.7 이전에 사용하던 방신.
     * 5.7 이후 버전에서는 HttpConfigBuilder에서 expressionHander를 등록하면 되는 것으로 추정됨. 테스트 해봐야 할듯.
     * TODO: 어떤 로직을 수행하는지 확인 필요. 참고 URL: https://www.baeldung.com/role-and-privilege-for-spring-security-registration
     *
     * DefaultWebSecurityExpressionHandler 클래스가 spring security에서 default로 권한체 크하는 클래스임.
     * 참고 글: https://ncucu.me/109
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
     * url 접근 제어 설정
     *
     * @return
     */
    @Bean
    public FilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() {
        /**
         * ConfigAttribute 직접 설정할 경우, RoleHierarchyVoter 에서 default는 역할은 ROLE_로 시작한다.
         * user builder를 통해 user의 역할을 추가할 경우 자동으로 ROLE_이 붙기 때문이다.
         */
        LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = new LinkedHashMap<>();

        requestMap.put(new AntPathRequestMatcher("/admin"), org.springframework.security.access.SecurityConfig.createList("ROLE_ADMIN"));
        requestMap.put(new AntPathRequestMatcher("/manager"), org.springframework.security.access.SecurityConfig.createList("ROLE_MANAGER"));

        //TODO ROLE_MANAGER 권한으로 /updateUser 접근 시 FilterSecurityInterceptor 클래스에서 invoke 호출 시 "Did not switch RunAs authentication since RunAsManager returned null" 메시지 발생 확인 필요
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
         * 사용자 생성 시점에  authorities 추가하게 되면 role은 무시되게 됨.
         * role에 해당하는 authorities 조회해서 세팅하기 때문에
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
