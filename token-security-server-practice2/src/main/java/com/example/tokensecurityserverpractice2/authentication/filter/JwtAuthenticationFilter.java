package com.example.tokensecurityserverpractice2.authentication.filter;

import com.example.tokensecurityserverpractice2.authentication.UsernamePasswordAuthentication;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Value("${jwt.signing.key}")
    private String signingKey;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String jwt = request.getHeader("Authorization");

        SecretKey key = Keys.hmacShaKeyFor(signingKey.getBytes(StandardCharsets.UTF_8));

        // 토큰을 구문분석해 클레임을 걸고 서명을 검증한다. 서명이 유요하지 않으면 예외가 투척된다.
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(jwt)
                .getBody();

        String username = String.valueOf(claims.get("username"));

        // SecurityContext에 추가할 Authentication 인스턴스를 만든다.
        GrantedAuthority a = new SimpleGrantedAuthority("user");
        var auth = new UsernamePasswordAuthentication(username, null, List.of(a));
        // SecurityContext에 Authentication 추가
        SecurityContextHolder.getContext().setAuthentication(auth);
        // 필터 체인의 다음 필터를 호출한다.
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getServletPath().equals("/login");
    }
}
