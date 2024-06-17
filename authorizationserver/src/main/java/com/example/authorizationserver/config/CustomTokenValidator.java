package com.example.authorizationserver.config;

import lombok.RequiredArgsConstructor;

// 토큰의 유효성을 검증하는 커스텀 로직
// @Service
@RequiredArgsConstructor
public class CustomTokenValidator {
//  implements ResourceServerTokenServices {
  
  // private final TokenStore tokenStore;

  // @Override
  // public OAuth2AccessToken readAccessToken(String accessToken) {
  //     return tokenStore.readAccessToken(accessToken);
  // }

  // @Override
  // public OAuth2Authentication loadAuthentication(String accessToken) {
  //     OAuth2AccessToken token = tokenStore.readAccessToken(accessToken);
  //     System.out.println("loadAuthentication : "+accessToken);
  //     if (token == null || token.isExpired()) {
  //         throw new InvalidTokenException("loadAuthentication : Invalid or expired token");
  //     }
  //     return tokenStore.readAuthentication(accessToken);
  // }
}
