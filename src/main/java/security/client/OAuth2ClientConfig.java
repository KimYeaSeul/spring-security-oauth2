package security.client;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class OAuth2ClientConfig {

  @Bean
  public SecurityFilterChain SecurityFilterChain(HttpSecurity http) throws Exception{
      http.authorizeRequests(requests -> requests.anyRequest().authenticated());
      http.oauth2Login();

    return http.build();
  }
}
