package com.example.authorizationserver.utils;

import java.security.interfaces.RSAPrivateKey;
import java.util.*;

import com.example.authorizationserver.config.KeyConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;

import java.security.KeyPair;

import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;


import lombok.extern.slf4j.Slf4j;

@Slf4j
//@Configuration
public class CustomTokenConverter {
//  extends JwtAccessTokenConverter {
//
//  @Autowired
//  private TokenUtil tokenUtil;
//
//  @Override
//  public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
//    log.info("JwtAccessTokenConverter 입니다!");
//
//    if (authentication.getOAuth2Request().getGrantType().equals("password")) {
//      log.info("authentication.getPrincipal() : {}",authentication.getPrincipal().toString());
//
//      String jwtAccessToken = tokenUtil.generateAccessToken(authentication);
//      OAuth2RefreshToken jwtRefreshToken = tokenUtil.generateRefreshToken(authentication);
//      ((DefaultOAuth2AccessToken) accessToken).setValue(jwtAccessToken);
//      ((DefaultOAuth2AccessToken) accessToken).setRefreshToken(jwtRefreshToken);
//    }
////    return super.enhance(accessToken, authentication);
//    return accessToken;
//  }
//
//    private JsonParser objectMapper = JsonParserFactory.create();
//
//    final RsaSigner signer = new RsaSigner(KeyConfig.getSignerKey());

//    @Override
//    protected String encode(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
//        System.out.println("get Token = "+ accessToken.getValue());
//        if (authentication.getOAuth2Request().getGrantType().equals("password")) {
//            System.out.println("encode 누가먼저냐 22222222 authentication.getPrincipal() : {}" + authentication.getPrincipal().toString());
//            String content;
//            try {
//                content = this.objectMapper.formatMap(getAccessTokenConverter().convertAccessToken(accessToken, authentication));
//                System.out.println("contetn=    = = = = = " + content);
//            } catch (Exception ex) {
//                throw new IllegalStateException("Cannot convert access token to JSON", ex);
//            }
//            Map<String, String> headers = new HashMap<>();
//            headers.put("kid", KeyConfig.VERIFIER_KEY_ID);
//            String token = JwtHelper.encode(content, signer, headers).getEncoded();
//            return token;
//        }
//        return accessToken.getValue();
//    }
}
