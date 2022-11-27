package com.kurt.practice.springbootsecuritypractice.config;

import com.kurt.practice.springbootsecuritypractice.controller.HelloController;
import jdk.jfr.Enabled;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Import({UserManagementConfig.class, WebAuthorizationConfig.class, CustomAuthenticationProvider.class})
@WebMvcTest(HelloController.class)
@DisplayName("AuthenticationProivder가 어떻게 동작하는지 간단하게 확인했고 CustomAuthenticationProvider를 적용해보았으로 제외")
@Disabled
public class CustomAuthenticationTest {

    @Autowired
    private MockMvc mvc;
    @Test
    @DisplayName("Test calling /hello endpoint authenticating with valid credentials returns ok.")
    public void helloAuthenticatingWithValidUser() throws Exception {
        mvc.perform(get("/hello")
                        .with(httpBasic("john", "12345")))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Test calling /hello endpoint authenticating with wrong credentials returns unauthorized.")
    public void helloAuthenticatingWithInvalidUser() throws Exception {
        mvc.perform(get("/hello")
                        .with(httpBasic("mary", "12345")))
                .andExpect(status().isUnauthorized());
    }

}
