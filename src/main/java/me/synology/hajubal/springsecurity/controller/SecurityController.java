package me.synology.hajubal.springsecurity.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index() {
        return "home" + ", user info: "+SecurityContextHolder.getContext().getAuthentication().getName();
    }

    @GetMapping("/user")
    public String user() {
        return "user" + ", user info: "+SecurityContextHolder.getContext().getAuthentication().getName();
    }

    @GetMapping("/sys")
    public String sys() {
        return "sys" + ", user info: "+SecurityContextHolder.getContext().getAuthentication().getName();
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin" + ", user info: "+SecurityContextHolder.getContext().getAuthentication().getName();
    }

    @GetMapping("/denied")
    public String denied() {
        return "denied";
    }

    @GetMapping("/info")
    public String info() {
        return "user info: "+SecurityContextHolder.getContext().getAuthentication().getName();
    }
}
