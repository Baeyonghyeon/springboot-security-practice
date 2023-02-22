package com.example.tokensecurityserverpractice.service;

import com.example.tokensecurityserverpractice.entity.Otp;
import com.example.tokensecurityserverpractice.entity.Users;
import com.example.tokensecurityserverpractice.repository.OtpRepository;
import com.example.tokensecurityserverpractice.repository.UserRepository;
import com.example.tokensecurityserverpractice.util.GenerateCodeUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.Optional;

@Slf4j
@Service
@Transactional
public class UserService {

    public UserService(PasswordEncoder passwordEncoder, UserRepository userRepository, OtpRepository otpRepository) {
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.otpRepository = otpRepository;
    }

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final OtpRepository otpRepository;

    public void addUser(Users user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
    }

    public void auth(Users user) {
        log.info("로그인 시도할 아이디를 확인합니다. : {}", user.getUsername());
        userRepository.findUsersByUsername(user.getUsername())
                .filter(u -> passwordEncoder.matches(user.getPassword(), u.getPassword()))
                .ifPresentOrElse(this::renewOtp,
                        () -> {
                            throw new BadCredentialsException("Bad credentials");
                        });
    }


    private void renewOtp(Users u) {
        log.info("OTP 4자리 생성중...");
        String code = GenerateCodeUtil.generateCode();

        otpRepository.findOtpByUsername(u.getUsername())
                .ifPresentOrElse(o -> o.setCode(code),
                        () -> {
                            Otp otp = new Otp();
                            otp.setUsername(u.getUsername());
                            otp.setCode(code);
                            otpRepository.save(otp);
                        });
    }


    public boolean check(Otp otpToValidate) {
        Optional<Otp> userOtp =
                otpRepository.findOtpByUsername(otpToValidate.getUsername());

        if (userOtp.isPresent()){
            Otp otp = userOtp.get();
            return otpToValidate.getCode().equals(otp.getCode());
        }

        return false;
    }
}
