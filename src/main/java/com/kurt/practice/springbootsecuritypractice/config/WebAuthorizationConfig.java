package com.kurt.practice.springbootsecuritypractice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class WebAuthorizationConfig {

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authz -> authz
                        .anyRequest().authenticated())
                .httpBasic();
        

        return http.build();
    }

    // authenticate 의 인증 메서드를 제공하는 매니저
    @Bean
    public AuthenticationManager authenticationManager () {
        return new ProviderManager(customAuthenticationProvider());
    }

    // 인증 제공자. 구현에 따라 다르겠지만 username, password 요구하게 작성되어 있음.
    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider(){
        return new CustomAuthenticationProvider();
    }
}
