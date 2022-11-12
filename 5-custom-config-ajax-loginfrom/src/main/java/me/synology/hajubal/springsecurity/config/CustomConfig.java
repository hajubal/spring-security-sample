package me.synology.hajubal.springsecurity.config;

import me.synology.hajubal.springsecurity.filter.AjaxLoginProcessingFilter;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class CustomConfig<H extends HttpSecurityBuilder<H>> extends
        AbstractAuthenticationFilterConfigurer<H, CustomConfig<H>, AjaxLoginProcessingFilter> {
    @Override
    protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
        return new AntPathRequestMatcher(loginProcessingUrl, "POST");
    }
}
