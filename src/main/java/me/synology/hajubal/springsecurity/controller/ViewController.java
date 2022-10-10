package me.synology.hajubal.springsecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ViewController {

    @GetMapping("/loginPage")
    public String login() {
        return "login";
    }
}
