package com.example.authorizationserver.domain;

import javax.transaction.Transactional;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

  private final RefreshTokenRepository refreshTokenRepository;

  @Transactional
  public void saveTokenInfo(){
    
  }

  @Transactional
  public void removeRefreshToken(String accessToken){
    RefreshToken token = refreshTokenRepository.findByAccessToken(accessToken).orElseThrow(IllegalArgumentException::new);

    refreshTokenRepository.delete(token);
  }
}
