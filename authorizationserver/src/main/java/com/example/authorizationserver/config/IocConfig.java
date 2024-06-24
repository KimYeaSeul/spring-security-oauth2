package com.example.authorizationserver.config;

import com.example.authorizationserver.custom.CustomJdbcTokenStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class IocConfig {
    
    private final DataSource dataSource;

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    
    // 기본 JDBC 토큰 저장소
    @Primary
    @Bean
    JdbcTokenStore jdbcTokenStore() {
        return new CustomJdbcTokenStore(dataSource);
    }

    // JWT 토큰 저장
    @Bean
    JwtTokenStore jwtTokenStore() {
        JwtTokenStore tokenStore = new JwtTokenStore(accessTokenConverter());
        tokenStore.setApprovalStore(approvalStore());
        return tokenStore;
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        final RsaSigner signer = new RsaSigner(KeyConfig.getSignerKey());

        JwtAccessTokenConverter converter = new JwtAccessTokenConverter() {
            private JsonParser objectMapper = JsonParserFactory.create();

            @Override
            protected String encode(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
               log.info("get Token = {}", accessToken.getValue());
                    String content;
                    try {
                        content = this.objectMapper.formatMap(getAccessTokenConverter().convertAccessToken(accessToken, authentication));
                        log.info("contetn=    {} ", content);
                    } catch (Exception ex) {
                        throw new IllegalStateException("Cannot convert access token to JSON", ex);
                    }
                    Map<String, String> headers = new HashMap<>();
                    headers.put("kid", KeyConfig.VERIFIER_KEY_ID);
                    String token = JwtHelper.encode(content, signer, headers).getEncoded();
                    return token;
            }

//            @Override
//            public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
//                System.out.println("encode 누가먼저냐 11111111 ");
////                if (authentication.getOAuth2Request().getGrantType().equals("password")) {
////                    System.out.println("authentication.getPrincipal() : "+authentication.getPrincipal().toString());
//
////                    String jwtAccessToken = tokenUtil.generateAccessToken(authentication);
////                    OAuth2RefreshToken jwtRefreshToken = tokenUtil.generateRefreshToken(authentication);
////                    ((DefaultOAuth2AccessToken) accessToken).setValue(jwtAccessToken);
////                    ((DefaultOAuth2AccessToken) accessToken).setRefreshToken(jwtRefreshToken);
////                }
////    return super.enhance(accessToken, authentication);
////                return accessToken;
//                return super.enhance(accessToken, authentication);
//            }
        };
        converter.setSigner(signer);
        converter.setVerifier(new RsaVerifier(KeyConfig.getVerifierKey()));
        return converter;
    }

    @Bean
    public ApprovalStore approvalStore() {
        return new JdbcApprovalStore(dataSource);
    }
}
