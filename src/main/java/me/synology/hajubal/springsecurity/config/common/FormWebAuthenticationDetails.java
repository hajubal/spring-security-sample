package me.synology.hajubal.springsecurity.config.common;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

/**
 * login 할 때 client로 부터 넘어온 데이터를 저장하는 클래스
 */
public class FormWebAuthenticationDetails extends WebAuthenticationDetails {

    private String secretKey;

    public FormWebAuthenticationDetails(HttpServletRequest request) {
        super(request);

        this.secretKey = request.getParameter("secret_key");
    }

    public String getSecretKey() {
        return this.secretKey;
    }
}
