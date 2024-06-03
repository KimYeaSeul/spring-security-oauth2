package com.example.authorizationserver.domain;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
@RequiredArgsConstructor
@Service
public class UserService {

  private final UserRepository userRepository;
  private final OauthClientDetailsRepository clientRepository;
  private final PasswordEncoder passwordEncoder;

  public User registerUser(String username, String password) {
    User user = new User();
    user.setUsername(username);
    user.setPassword(passwordEncoder.encode(password));
    user.setEnabled(true);
    // Set roles as needed
    return userRepository.save(user);
  }

  // builder 패턴이나 함수로 변경 필요
  public OauthClientDetails registerClient(String clientId, String clientSecret, String authorizedGrantTypes, String scopes) {
    OauthClientDetails client = new OauthClientDetails();
    client.setClient_id(clientId);
    client.setClient_secret(passwordEncoder.encode(clientSecret));
    client.setAuthorized_grant_types(authorizedGrantTypes);
    client.setScope(scopes);
    return clientRepository.save(client);
}
}
