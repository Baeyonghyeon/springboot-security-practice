package com.example.tokensecurityserverpractice2.authentication.config;

import com.example.tokensecurityserverpractice2.authentication.filter.InitialAuthenticationFilter;
import com.example.tokensecurityserverpractice2.authentication.filter.JwtAuthenticationFilter;
import com.example.tokensecurityserverpractice2.authentication.provider.OtpAuthenticationProvider;
import com.example.tokensecurityserverpractice2.authentication.provider.UsernamePasswordAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@RequiredArgsConstructor
@Configuration
public class SecurityConfig {

    private final OtpAuthenticationProvider otpAuthenticationProvider;
    private final UsernamePasswordAuthenticationProvider usernamePasswordAuthenticationProvider;

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authBuilder.authenticationProvider(otpAuthenticationProvider);
        authBuilder.authenticationProvider(usernamePasswordAuthenticationProvider);
        return authBuilder.build();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .addFilterAt(new InitialAuthenticationFilter(authenticationManager(http)), BasicAuthenticationFilter.class)
                .addFilterAfter(new JwtAuthenticationFilter(), BasicAuthenticationFilter.class)
                .authorizeHttpRequests().anyRequest().authenticated();

        return http.build();
    }

}