package com.example.tokensecurityserverpractice2.authentication.filter;

import com.example.tokensecurityserverpractice2.authentication.OtpAuthentication;
import com.example.tokensecurityserverpractice2.authentication.UsernamePasswordAuthentication;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class InitialAuthenticationFilter extends OncePerRequestFilter {

    public final AuthenticationManager authenticationManager;

    @Value("${jwt.signing.key}")
    private String signingKey;

    public InitialAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String username = request.getHeader("username");
        String password = request.getHeader("password");
        String code = request.getHeader("code");

        if (code == null) { // HTTP 요청에 OTP 가 없으면 사용자 이름과 암호로 인증해야 한다고 가정한다.
            Authentication a = new UsernamePasswordAuthentication(username, password);
            authenticationManager.authenticate(a);
        }

        // 클라이언트가 OTP 를 보냈다고 가정.
        Authentication a = new OtpAuthentication(username, code);
        a = authenticationManager.authenticate(a);

        SecretKey key = Keys.hmacShaKeyFor(signingKey.getBytes(StandardCharsets.UTF_8));

        // JWT를 구축하고 안중된 사용자의 사용자 이름을 클레임중 하나로 저장한다.
        // 토큰을 서명하는 데 키를 이용했다.
        String jwt = Jwts.builder()
                .setClaims(Map.of("username", username)) // JWT 본문에 값 추가
                .signWith(key)                                  // 토큰에 서명 추가
                .compact();
        response.setHeader("Authorization", jwt);

    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return !request.getServletPath().equals("/login"); // "/login" 경로만 이 필터를 적용
    }
}
