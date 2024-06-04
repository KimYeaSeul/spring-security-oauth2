package com.example.authorizationserver.domain;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken,String>  {

  Optional<RefreshToken> findByAccessToken(String accessToken);
}
