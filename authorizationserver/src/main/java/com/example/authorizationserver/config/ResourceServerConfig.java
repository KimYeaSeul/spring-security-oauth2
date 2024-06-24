package com.example.authorizationserver.config;

import com.example.authorizationserver.domain.ResourceIdService;
import com.example.authorizationserver.filter.CustomResourceIdFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.logging.Logger;

@Configuration
@EnableResourceServer
@RequiredArgsConstructor 
public class ResourceServerConfig extends ResourceServerConfigurerAdapter{

    private final ResourceIdService resourceIdService;

    @Override
    public void configure(ResourceServerSecurityConfigurer security) throws Exception {
        security
                .resourceId(null);
    }

  @Override
  public void configure(HttpSecurity http) throws Exception {
      http.authorizeRequests(requests -> requests
              .antMatchers("/oauth/**").hasAnyAuthority("ADMIN")
              .anyRequest().authenticated())
              .addFilterBefore(new CustomResourceIdFilter(resourceIdService), UsernamePasswordAuthenticationFilter.class);
  }
}
