package com.example.tokensecurityserverpractice.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter // 실제 로직에선 Setter 를 사용하지 않지만 구현을 간단하게 하기 위해 사용
@Entity
public class Otp {

    @Id
    private String username;

    private String code;
}
