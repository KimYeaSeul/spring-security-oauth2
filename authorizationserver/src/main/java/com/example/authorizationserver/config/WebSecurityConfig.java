package com.example.authorizationserver.config;
import static org.springframework.security.config.Customizer.*;

import com.example.authorizationserver.custom.CustomUserDetailsService;
import com.example.authorizationserver.utils.CustomTokenConverter;
import com.example.authorizationserver.utils.TokenUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.authorizationserver.filter.AuthFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{
    private final CustomUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
                .authorizeRequests((authz) -> authz
                                .antMatchers("/oauth2/client/join").permitAll()
                                .antMatchers("/oauth2/keys").permitAll()
                                .anyRequest().authenticated()
                )
                .formLogin(login -> login.disable()) // 폼로그인 비활성화
                .httpBasic(withDefaults()) // 기본 인증 사용
                ;
    }
    
    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
        .userDetailsService(userDetailsService)
        .passwordEncoder(passwordEncoder); // provider 의 passwordencoder
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
