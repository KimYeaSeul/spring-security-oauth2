package com.example.authorizationserver.config;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

/* 
    인증 처리를 위한 핵심 컴포넌트
  */
@Component
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

  private final CustomUserDetailsService userDetailsService;
  private final PasswordEncoder passwordEncoder;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    String username = authentication.getName();
    System.out.println("프로바이더 입니다.!!! 유저정보찾기   "+username);

        String password = (String) authentication.getCredentials();
        String encPw = passwordEncoder.encode(password);
        UserDetails user = userDetailsService.loadUserByUsername(username);

        System.out.println("어떤 유저가 들어온걸까요 ? "+user.toString());
        
        System.out.println("tablePassword = "+user.getPassword());
        System.out.println("getPassword = "+password);
        System.out.println("getPassword = "+encPw);
        if (user == null || !BCrypt.checkpw( password, user.getPassword())) {
            throw new UsernameNotFoundException("CustomAuthenticationProvider Invalid username or password");
        }

        return new UsernamePasswordAuthenticationToken(user, password, user.getAuthorities());
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
  }

}
