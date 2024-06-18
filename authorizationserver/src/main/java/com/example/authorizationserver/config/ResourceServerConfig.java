package com.example.authorizationserver.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

import lombok.RequiredArgsConstructor;
@Configuration
@EnableResourceServer
@RequiredArgsConstructor 
public class ResourceServerConfig extends ResourceServerConfigurerAdapter{

  @Override
  public void configure(HttpSecurity http) throws Exception {
      http.authorizeRequests(requests -> requests
              .antMatchers("/oauth/test").authenticated()
              .anyRequest().permitAll());
  }
}
