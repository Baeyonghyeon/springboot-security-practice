package com.example.tokensecurityserverpractice2.authentication.config;

import com.example.tokensecurityserverpractice2.authentication.filter.InitialAuthenticationFilter;
import com.example.tokensecurityserverpractice2.authentication.filter.JwtAuthenticationFilter;
import com.example.tokensecurityserverpractice2.authentication.provider.OtpAuthenticationProvider;
import com.example.tokensecurityserverpractice2.authentication.provider.UsernamePasswordAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@RequiredArgsConstructor
@Configuration
public class SecurityConfig {

    private final InitialAuthenticationFilter initialAuthenticationFilter;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final OtpAuthenticationProvider otpAuthenticationProvider;
    private final UsernamePasswordAuthenticationProvider usernamePasswordAuthenticationProvider;

    @Bean
    protected AuthenticationManagerBuilder configure(AuthenticationManagerBuilder auth) {
        return auth
                .authenticationProvider(otpAuthenticationProvider)
                .authenticationProvider(usernamePasswordAuthenticationProvider);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
    }
}
