package com.kurt.practice.springbootsecuritypractice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public class WebAuthorizaionConfig {

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authz ->
                        authz.anyRequest().authenticated())
                .httpBasic();

        return http.build();
    }
}
