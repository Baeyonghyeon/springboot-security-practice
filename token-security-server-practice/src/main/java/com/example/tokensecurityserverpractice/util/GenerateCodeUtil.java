package com.example.tokensecurityserverpractice.util;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class GenerateCodeUtil {

    public static String generateCode() {
        String code;

        try {
            // 임의의 int 값을 생성하는 SecurityRandom의 인스턴스를 만든다.
            SecureRandom random = SecureRandom.getInstanceStrong();
            // 0 ~ 8999 사이의 값을 생성하고 1000을 더해서 1000 ~ 9999(4자리 임의 코드) 사이의 값을 얻는다.
            int c = random.nextInt(9000) + 1000;
            code = String.valueOf(c);

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Problem when generating the random code.");
        }

        return code;
    }

}
