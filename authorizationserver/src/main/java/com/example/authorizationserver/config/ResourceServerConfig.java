package com.example.authorizationserver.config;

import com.example.authorizationserver.domain.UserService;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.util.logging.Logger;

@Configuration
@EnableResourceServer
@RequiredArgsConstructor 
public class ResourceServerConfig extends ResourceServerConfigurerAdapter{

    Logger log = Logger.getLogger(ResourceServerConfig.class.getName());

//    @Override
//    public void configure(ResourceServerSecurityConfigurer security) throws Exception {
//        security
//                .resourceId("ECOMMERCE");
//    }

  @Override
  public void configure(HttpSecurity http) throws Exception {
      http.authorizeRequests(requests -> requests
              .antMatchers("/oauth/test").authenticated()
              .anyRequest().permitAll());
  }
}
