package com.example.authorizationserver.user;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.authorizationserver.domain.User;

public interface UserRepository extends JpaRepository<User, Long> {
  Optional<User> findByUsername(String username);

}
