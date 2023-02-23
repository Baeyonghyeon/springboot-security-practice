package com.example.tokensecurityserverpractice2.authentication.provider;

import com.example.tokensecurityserverpractice2.authentication.UsernamePasswordAuthentication;
import com.example.tokensecurityserverpractice2.authentication.proxy.AuthenticationServerProxy;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class UsernamePasswordAuthenticationProvider implements AuthenticationProvider {

    private final AuthenticationServerProxy proxy;

    public UsernamePasswordAuthenticationProvider(AuthenticationServerProxy proxy) {
        this.proxy = proxy;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = String.valueOf(authentication.getCredentials());

        proxy.sendAuth(username, password);

        return new UsernamePasswordAuthenticationToken(username, password);
    }

    // 지원하는 인증 클래스
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthentication.class.isAssignableFrom(authentication);
    }
}
