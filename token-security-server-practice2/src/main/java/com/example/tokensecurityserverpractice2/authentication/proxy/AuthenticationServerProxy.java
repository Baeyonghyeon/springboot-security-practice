package com.example.tokensecurityserverpractice2.authentication.proxy;

import com.example.tokensecurityserverpractice2.authentication.model.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.RestTemplate;

public class AuthenticationServerProxy {

    @Value("${auth.server.base.url}")
    private String baseUrl;

    private final RestTemplate restTemplate;

    public AuthenticationServerProxy(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public void sendAuth(String username, String password) {
        String url = baseUrl + "/user/auth";

        var body = new User();
        body.setUsername(username);
        body.setPassword(password);

        var request = new HttpEntity<>(body);

        restTemplate.postForEntity(url, request, Void.class);
    }

    public boolean sendOTP(String username, String code){

        String url = baseUrl + "/otp/check";

        var body = new User();
        body.setUsername(username);
        body.setPassword(code);

        var request  = new HttpEntity<>(body);

        var response = restTemplate.postForEntity(url, request, Void.class);

        return response.getStatusCode().equals(HttpStatus.OK);
    }

}
