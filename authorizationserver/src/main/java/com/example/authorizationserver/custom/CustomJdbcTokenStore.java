package com.example.authorizationserver.custom;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

import javax.sql.DataSource;

public class CustomJdbcTokenStore extends JdbcTokenStore {

    public CustomJdbcTokenStore(DataSource dataSource) {
        super(dataSource);
    }

    @Override
    public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
        OAuth2AccessToken existAccessToken = super.getAccessToken(authentication);
        System.out.println("existAccessToken = "+existAccessToken.getValue());
        if (existAccessToken != null) {
            this.removeAccessToken(existAccessToken);
        }
        return super.getAccessToken(authentication);
    }
}