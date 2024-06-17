package com.example.authorizationserver.config;
import java.util.Collections;

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
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import lombok.RequiredArgsConstructor;
/*
 * 클라이언트 자격 증명 방식을 사용하여 클라이언트 인증
 */
@Configuration
@RequiredArgsConstructor
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    // 1. client와 user 회원가입 방식 다르게 적용하기
    // 2. 내가 원하는 방식대로 토큰이 나오게 적용하기?
    // 3. 유저 회원가입 시 토큰 검증

    private final JwtTokenProvider jwtTokenProvider;
	private final AuthenticationManager authenticationManager;
    private final CustomClientDetailsService clientDetailsService;
    private final CustomUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final DefaultTokenServices jdbcTokenServices;
    private final JdbcTokenStore jdbcTokenStore;
    private final JwtTokenStore jwtTokenStore;
    private final DataSource dataSource;

    // @Override
    // public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
    //     endpoints.authenticationManager(authenticationManager);
    // }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        // TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        // tokenEnhancerChain.setTokenEnhancers(Arrays.asList(jwtTokenEnhancer(), accessTokenConverter()));

        CustomTokenService tokenServices = new CustomTokenService(jdbcTokenStore, jwtTokenStore);

        tokenServices.setTokenEnhancer(jwtTokenEnhancer());
        
        endpoints
            .authenticationManager(authenticationManager)
            .tokenServices(tokenServices);
            // .tokenStore(jdbcTokenStore)
            // .accessTokenConverter(accessTokenConverter())
            // .tokenEnhancer(tokenEnhancerChain)
            // .tokenStore
            // .tokenServices(jdbcTokenServices)
            // .userDetailsService(userDetailsService)
            // .tokenStore(jdbcTokenStore());
            // .tokenServices(jwtTokenServices()) // 클라이언트 자격 증명 방식의 엔드포인트 설정
            // .tokenStore(jwtTokenStore()) // 패스워드 방식의 엔드포인트 설정
    }


    @Bean
    TokenEnhancer jwtTokenEnhancer() {
        // return new CustomTokenEnhancer();
        return new JwtAccessTokenConverter() {
            @Override
            public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
                System.out.println("자자자ㅏ tokenenhance 입니다! "+ authentication.getOAuth2Request().getGrantType());
                if (authentication.getOAuth2Request().getGrantType().equals("password")) {
                    
                System.out.println("패스워드 방식이군요!");
                    String jwtToken = jwtTokenProvider.generateToken(authentication);
                    ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(Collections.singletonMap("customInfo", "someValue"));
                    ((DefaultOAuth2AccessToken) accessToken).setValue(jwtToken);
                }
                return accessToken;
            }
        };
    }

    private static class CustomTokenEnhancer implements TokenEnhancer {
        @Override
        public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
            // 사용자 인증 방식에 대해서만 JWT로 변환
            if ("password".equals(authentication.getOAuth2Request().getGrantType())) {
                ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(Collections.singletonMap("customInfo", "someValue"));
            }
            return accessToken;
        }
    }

    // @Bean
    // JwtAccessTokenConverter accessTokenConverter() {
    //     return new JwtAccessTokenConverter() {
    //         @Override
    //         public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
    //             ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(Collections.singletonMap("customInfo", "someValue"));
    //             String jwt = jwtTokenProvider.generateToken(authentication); 
    //             ((DefaultOAuth2AccessToken) accessToken).setValue(jwt);
    //             return accessToken;
    //         }
    //     };
    // }

    // JWT 토큰 서비스 (패스워드 방식용)
    // @Bean
    // DefaultTokenServices jwtTokenServices() {
    //     DefaultTokenServices tokenServices = new DefaultTokenServices();
    //     tokenServices.setTokenStore(jwtTokenStore());
    //     tokenServices.setTokenEnhancer(jwtTokenEnhancer());
    //     return tokenServices;
    // }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        // 토큰유효성(/token/check_token) 접근을 위해 설정
        security
                .checkTokenAccess("isAuthenticated()")
                .tokenKeyAccess("permitAll()");
                // .passwordEncoder(passwordEncoder)
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(clientDetailsService);
        clients.jdbc(dataSource).passwordEncoder(passwordEncoder);
    }
}