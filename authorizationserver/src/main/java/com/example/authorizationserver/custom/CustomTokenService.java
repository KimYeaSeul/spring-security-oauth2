package com.example.authorizationserver.custom;

import org.jboss.logging.Logger;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class CustomTokenService extends DefaultTokenServices {
    
  private final JdbcTokenStore jdbcTokenStore;
  private final JwtTokenStore jwtTokenStore;
  private final Logger log = Logger.getLogger(CustomTokenService.class);

  @Override
  public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {
      if ("client_credentials".equals(authentication.getOAuth2Request().getGrantType())) {
        log.info("클라이언트크레덴셜이다!!!!!!!!!");
          this.setTokenStore(jdbcTokenStore);
      } else if ("password".equals(authentication.getOAuth2Request().getGrantType())) {
        log.info("패스워드다ㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏ");
          this.setTokenStore(jwtTokenStore);
      } else {
          this.setTokenStore(jdbcTokenStore); // Default to JdbcTokenStore
      }
      return super.createAccessToken(authentication);
  }
}
