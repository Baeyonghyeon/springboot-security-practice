package com.kurt.practice.springbootsecuritypractice.config;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.Arrays;

//@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    /**
     * 인증 논리를 추가할 위치
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
         // Principal 인터페이스의 getName() 메서드를 Authentication 에서 상속 받는다.
        String username = authentication.getName();
        String password = String.valueOf(authentication.getCredentials());

        // 일반 적으로 해당 조건은 UserDetailsService 및 PasswordEncoder를 호출해서 사용자 이름과 암호를 테스트 한다.
        if ("john".equals(username) && "12345".equals(password)) {
            return new UsernamePasswordAuthenticationToken(username, password, Arrays.asList());
        } else {
            throw new AuthenticationCredentialsNotFoundException("Error!");
        }
    }

    /**
     * Authentication 형식의 구현을 추가할 위치
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
