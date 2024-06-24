package com.example.authorizationserver.custom;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class CustomTokenService extends DefaultTokenServices {

    private final JwtTokenStore jwtTokenStore;
    private final JdbcTokenStore jdbcTokenStore;
    private final JwtAccessTokenConverter jwtAccessTokenConverter;

    @Override
     public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {
         String grantType = authentication.getOAuth2Request().getGrantType();
         if ("client_credentials".equals(grantType)) {
               this.setTokenStore(jdbcTokenStore);
               this.setTokenEnhancer(null);
         } else if ("password".equals(grantType)) {
               this.setTokenStore(jwtTokenStore);
               this.setTokenEnhancer(jwtAccessTokenConverter);
         } else {
               this.setTokenStore(jdbcTokenStore);
               this.setTokenEnhancer(null);
         }
         return super.createAccessToken(authentication);
     }

    @Override
    public OAuth2AccessToken refreshAccessToken(String refreshTokenValue, TokenRequest tokenRequest) throws AuthenticationException {
        this.setTokenStore(jwtTokenStore);
        this.setTokenEnhancer(jwtAccessTokenConverter);
        return super.refreshAccessToken(refreshTokenValue, tokenRequest);
    }
}
