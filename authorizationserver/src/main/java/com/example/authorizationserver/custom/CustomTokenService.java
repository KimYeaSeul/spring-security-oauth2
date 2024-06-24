package com.example.authorizationserver.custom;

import org.jboss.logging.Logger;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import lombok.RequiredArgsConstructor;

import java.util.Collections;

@RequiredArgsConstructor
public class CustomTokenService extends DefaultTokenServices {

    private final JwtTokenStore jwtTokenStore;
    private final JdbcTokenStore jdbcTokenStore;
    private final CustomeNullTokenEnhance nullTokenConverter;
    private final JwtAccessTokenConverter jwtAccessTokenConverter;
  private final Logger log = Logger.getLogger(CustomTokenService.class);

  @Override
  public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {
      String grantType = authentication.getOAuth2Request().getGrantType();
      if ("client_credentials".equals(grantType)) {
        log.info("클라이언트크레덴셜이다!!!!!!!!!");
          this.setTokenStore(jdbcTokenStore);
          TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
          tokenEnhancerChain.setTokenEnhancers(Collections.singletonList(nullTokenConverter));
          this.setTokenEnhancer(tokenEnhancerChain);

//          this.setTokenEnhancer(nullTokenConverter);
      } else if ("password".equals(grantType)) {
        log.info("패스워드다ㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏ");
          this.setTokenStore(jwtTokenStore);
          TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
          tokenEnhancerChain.setTokenEnhancers(Collections.singletonList(jwtAccessTokenConverter));
          this.setTokenEnhancer(tokenEnhancerChain);
//          this.setTokenEnhancer(jwtAccessTokenConverter);
      } else {
          this.setTokenStore(jdbcTokenStore); // Default to JdbcTokenStore
          TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
          tokenEnhancerChain.setTokenEnhancers(Collections.singletonList(nullTokenConverter));
          this.setTokenEnhancer(tokenEnhancerChain);
//          this.setTokenEnhancer(nullTokenConverter);

      }
      return super.createAccessToken(authentication);
  }
}
