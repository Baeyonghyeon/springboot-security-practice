package com.example.tokensecurityserverpractice2.authentication.config;

import com.example.tokensecurityserverpractice2.authentication.filter.InitialAuthenticationFilter;
import com.example.tokensecurityserverpractice2.authentication.filter.JwtAuthenticationFilter;
import com.example.tokensecurityserverpractice2.authentication.provider.OtpAuthenticationProvider;
import com.example.tokensecurityserverpractice2.authentication.provider.UsernamePasswordAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

@RequiredArgsConstructor
@Configuration
public class SecurityConfig {

    private final InitialAuthenticationFilter initialAuthenticationFilter;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final OtpAuthenticationProvider otpAuthenticationProvider;
    private final UsernamePasswordAuthenticationProvider usernamePasswordAuthenticationProvider;


}
