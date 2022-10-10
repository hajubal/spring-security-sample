package me.synology.hajubal.springsecurity.config;

import me.synology.hajubal.springsecurity.config.version.SecurityConfigV1;
import me.synology.hajubal.springsecurity.config.version.SecurityConfigV2;
import me.synology.hajubal.springsecurity.config.version.SecurityConfigV3;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

//@Import(SecurityConfigV3.class)
@Import(SecurityConfigV2.class)
//@Import(SecurityConfigV1.class)
@EnableWebSecurity
public class SecurityConfig {

}
