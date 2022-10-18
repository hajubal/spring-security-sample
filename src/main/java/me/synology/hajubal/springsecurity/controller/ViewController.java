package me.synology.hajubal.springsecurity.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ViewController {

    @GetMapping("/loginPage")
    public String login(@RequestParam(value = "error", required = false) String error,
                        @RequestParam(value = "exception", required = false) String exception,
                        Model model) {

        model.addAttribute("error", error);
        model.addAttribute("exception", exception);
        return "login";
    }

    @GetMapping("/denied")
    public String accessDenied(@RequestParam(name = "exception", required = false) String exception,
                               Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();


        model.addAttribute("exception", exception);

        return "denied";
    }
}
