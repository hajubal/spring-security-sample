package me.synology.hajubal.springsecurity.common;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

public class CustomWebAuthenticationDetails extends WebAuthenticationDetails {

    private String secretKey;

    public CustomWebAuthenticationDetails(HttpServletRequest request) {
        super(request);

        this.secretKey = request.getParameter("secretKey");
    }

    public String getSecretKey() {
        return secretKey;
    }
}
