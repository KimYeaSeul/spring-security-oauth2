package com.example.authorizationserver.custom;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/* 
    인증 처리를 위한 핵심 컴포넌트
  */
@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

  private final CustomUserDetailsService userDetailsService;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    String username = authentication.getName();
        log.info("DaoAuthenticationProvider  대신!! 유저 정보 : {}", username);

        String password = (String) authentication.getCredentials();
        UserDetails user = userDetailsService.loadUserByUsername(username);

        log.info("어떤 유저가 들어온걸까요 ? {}", user.toString());

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
