package com.example.authorizationserver.config;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.example.authorizationserver.custom.CustomJdbcTokenStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
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
import java.security.KeyPair;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

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

        JwtAccessTokenConverter converter = new JwtAccessTokenConverter() {
            private JsonParser objectMapper = JsonParserFactory.create();

            @Override
            protected String encode(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
                String content;
                try {
                    // PAYLOAD 여기서 변경!
                    content = this.objectMapper.formatMap(getAccessTokenConverter().convertAccessToken(accessToken, authentication));
//                    log.info("contetn=    {} ", content);
                } catch (Exception ex) {
                    throw new IllegalStateException("Cannot convert access token to JSON", ex);
                }
                Map<String, String> headers = new HashMap<>();
                headers.put("kid", KeyConfig.VERIFIER_KEY_ID);
                try {
                    JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .keyID(KeyConfig.VERIFIER_KEY_ID)
                            .build();

                    JWSObject jwsObject = new JWSObject(jwsHeader, new Payload(content));
                    jwsObject.sign(new RSASSASigner(KeyConfig.getKeyPair().getPrivate()));

                    return jwsObject.serialize();
                } catch (Exception e) {
                    throw new IllegalStateException("Cannot sign the token", e);
                }
            }

            @Override
            public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {

                OAuth2AccessToken enhancedToken  = super.enhance(accessToken, authentication);

                DefaultOAuth2AccessToken result = new DefaultOAuth2AccessToken(enhancedToken);
                Map<String, Object> addinfo = new LinkedHashMap<>(enhancedToken.getAdditionalInformation());
                // 추가 info 여기에 작성!!
//                info.put("asdf","asdf");
                result.setAdditionalInformation(addinfo);
                result.setValue(this.encode(result, authentication));

                return result;
            }
        };
        try {
            KeyPair keyPair = KeyConfig.getKeyPair();
            converter.setKeyPair(keyPair);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return converter;
    }

    @Bean
    public ApprovalStore approvalStore() {
        return new JdbcApprovalStore(dataSource);
    }
}
