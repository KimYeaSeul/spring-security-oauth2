package com.example.authorizationserver.config;


import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class IocConfig {
    
    private final DataSource dataSource;
    
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    // 기본 토큰 서비스 (클라이언트 자격 증명용)
    @Bean
    DefaultTokenServices jdbcTokenServices() {
        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setTokenStore(jdbcTokenStore());
        return tokenServices;
    }
    
    // 기본 JDBC 토큰 저장소
    @Bean
    @Primary
    JdbcTokenStore jdbcTokenStore() {
        return new JdbcTokenStore(dataSource);        
    }

    // JWT 토큰 저장
    @Bean
    JwtTokenStore jwtTokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }
    
    // JWT Access token 변환기
    @Bean
    JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey("signing-key");
        return converter;
    }
}
