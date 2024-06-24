package com.example.authorizationserver.config;

import javax.sql.DataSource;

import com.example.authorizationserver.custom.CustomClientDetailsService;
import com.example.authorizationserver.custom.CustomTokenService;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.ApprovalStoreUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import lombok.RequiredArgsConstructor;


/*
 * 클라이언트 자격 증명 방식을 사용하여 클라이언트 인증
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    private final DataSource dataSource;
    private final ApprovalStore approvalStore;
    private final JwtTokenStore jwtTokenStore;
    private final JdbcTokenStore jdbcTokenStore;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final CustomClientDetailsService clientDetailsService;
    private final JwtAccessTokenConverter customTokenConverter;

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        CustomTokenService tokenServices = new CustomTokenService(this.jwtTokenStore, this.jdbcTokenStore, this.customTokenConverter);
        tokenServices.setSupportRefreshToken(true);
        endpoints
            .authenticationManager(this.authenticationManager)
            .tokenServices(tokenServices)
            .userApprovalHandler(userApprovalHandler())
            .accessTokenConverter(this.customTokenConverter);
    }

    @Bean
    public UserApprovalHandler userApprovalHandler() {
        ApprovalStoreUserApprovalHandler userApprovalHandler = new ApprovalStoreUserApprovalHandler();
        userApprovalHandler.setApprovalStore(this.approvalStore);
        userApprovalHandler.setClientDetailsService(this.clientDetailsService);
        userApprovalHandler.setRequestFactory(new DefaultOAuth2RequestFactory(this.clientDetailsService));
        return userApprovalHandler;
    }

//    @Override
//    public void configure(AuthorizationServerSecurityConfigurer security) {
//        // 토큰유효성(/token/check_token) 접근을 위해 설정
//        security
//                .checkTokenAccess("isAuthenticated()")
//                .tokenKeyAccess("permitAll()");
//    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.jdbc(dataSource).passwordEncoder(passwordEncoder);
    }

    @Bean
    public JWKSet jwkSet() {
        RSAKey.Builder builder = new RSAKey.Builder(KeyConfig.getVerifierKey())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyID(KeyConfig.VERIFIER_KEY_ID);
        return new JWKSet(builder.build());
    }
}