package com.example.authorizationserver.config;
import java.util.Collections;

import javax.sql.DataSource;

import com.example.authorizationserver.custom.CustomClientDetailsService;
import com.example.authorizationserver.custom.CustomTokenService;
import com.example.authorizationserver.utils.JwtTokenUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
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
    private final JwtTokenUtil jwtTokenUtil;
    private final JwtTokenStore jwtTokenStore;
    private final JdbcTokenStore jdbcTokenStore;
    private final PasswordEncoder passwordEncoder;
	private final AuthenticationManager authenticationManager;
    private final CustomClientDetailsService clientDetailsService;

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

        CustomTokenService tokenServices = new CustomTokenService(jdbcTokenStore, jwtTokenStore);

        tokenServices.setTokenEnhancer(jwtTokenUtil);
        
        endpoints
            .authenticationManager(authenticationManager)
            .tokenServices(tokenServices);
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        // 토큰유효성(/token/check_token) 접근을 위해 설정
        security
                .checkTokenAccess("isAuthenticated()")
                .tokenKeyAccess("permitAll()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(clientDetailsService);
        clients.jdbc(dataSource).passwordEncoder(passwordEncoder);
    }
}