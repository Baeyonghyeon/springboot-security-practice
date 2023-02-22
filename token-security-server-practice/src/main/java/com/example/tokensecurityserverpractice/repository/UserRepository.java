package com.example.tokensecurityserverpractice.repository;

import com.example.tokensecurityserverpractice.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<Users, String> {

    Optional<Users> findUsersByUsername(String username);
}