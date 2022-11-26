package com.kurt.practice.springbootsecuritypractice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

public class UserManagementConfig {

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetailsService userDetailsService = new InMemoryUserDetailsManager();

        User user = (User) User.withUsername("kurt")
                .password("12345")
                .authorities("read")
                .build();

        ((InMemoryUserDetailsManager) userDetailsService).createUser(user);

        return userDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

}
