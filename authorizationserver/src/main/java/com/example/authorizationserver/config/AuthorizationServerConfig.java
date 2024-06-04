package com.example.authorizationserver.config;
import javax.sql.DataSource;

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
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import lombok.RequiredArgsConstructor;
/*
 * 클라이언트 자격 증명 방식을 사용하여 클라이언트 인증
 */
@SuppressWarnings("deprecation")
@Configuration
@RequiredArgsConstructor
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    private final JwtTokenProvider jwtTokenProvider;
    private final DataSource dataSource;
	private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    // @Override
    // public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
    //     endpoints.authenticationManager(authenticationManager);
    // }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
            .authenticationManager(authenticationManager)
            .tokenStore(tokenStore())
            .accessTokenConverter(accessTokenConverter());
    }

    @Bean
    JwtAccessTokenConverter accessTokenConverter() {
        return new JwtAccessTokenConverter() {
            @Override
            public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
                String jwt = jwtTokenProvider.generateToken(authentication);
                ((DefaultOAuth2AccessToken) accessToken).setValue(jwt);
                return accessToken;
            }
        };
    }

    @Bean
    TokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }
    
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        // 토큰유효성(/token/check_token) 접근을 위해 설정
        security.passwordEncoder(passwordEncoder)
                .checkTokenAccess("isAuthenticated()")
                .tokenKeyAccess("permitAll()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        System.out.println("데이터소스좀 보자요  " +dataSource.getConnection().getMetaData().getDatabaseProductName());
        clients.jdbc(dataSource).passwordEncoder(passwordEncoder);
        // String encCode = passwordEncoder.encode("clientSecret");
        // clients.inMemory()
        //         .withClient("clientId")
        //         .secret(encCode)
        //         .authorizedGrantTypes("password", "refresh_token")
        //         .scopes("read", "write")
        //         .accessTokenValiditySeconds(3600)
        //         .refreshTokenValiditySeconds(2592000);
    }
}