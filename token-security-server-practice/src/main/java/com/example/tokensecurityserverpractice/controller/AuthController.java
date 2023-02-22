package com.example.tokensecurityserverpractice.controller;

import com.example.tokensecurityserverpractice.entity.Otp;
import com.example.tokensecurityserverpractice.entity.Users;
import com.example.tokensecurityserverpractice.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/user/add")
    public void addUser(@RequestBody Users user){
        userService.addUser(user);
    }

    @PostMapping("/user/auth")
    public void auth(@RequestBody Users user){
        userService.auth(user);
    }

    // OTP가 유효하면 200, 그렇지 않으면 403 반환
    @PostMapping("/otp/check")
    public void check(@RequestBody Otp otp, HttpServletResponse response) {
        if(userService.check(otp)) {
            response.setStatus(HttpServletResponse.SC_OK);
        } else {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
    }
}
