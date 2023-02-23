package com.example.tokensecurityserverpractice2.authentication;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class UsernamePasswordAuthentication extends UsernamePasswordAuthenticationToken {
    /**
     * 처음 Authentication 객체를 구축할 때는 매개 변수가 2개인 생성자를 이용하여 아직 인증되지 않은 상태다.
     * AuthenticationProvider 객체가 요청을 인증할 때는 매배 변수가 3개인 생성자로
     * Authentication 인스턴스를 만들며 이때는 인증된 객체가 된다.
     * 세 번쨰 매개변수는 허가된 권한의 컬렉션이며 완료된 인증 프로세스에 필수다.
     */

    // 매개 변수가 2개는 인증 인스턴스가 인증되지 않은 상태로 유지
    public UsernamePasswordAuthentication(Object principal, Object credentials) {
        super(principal, credentials);
    }

    // 매개 변수가 3개인 생성자를 호출해야 인증 프로세스가 완료
    public UsernamePasswordAuthentication(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }
}
