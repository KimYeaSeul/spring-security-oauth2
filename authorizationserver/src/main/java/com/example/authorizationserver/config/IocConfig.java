package com.example.authorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class IocConfig {
    @Bean
    PasswordEncoder passwordEncoder(){
        // 같은 비밀번호여도 다르게 저장됨.
        // 이거면 충분한가?
        return new BCryptPasswordEncoder();
    }
}
