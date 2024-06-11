package com.example.authorizationserver.user;

import java.util.Optional;

import javax.transaction.Transactional;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.authorizationserver.domain.OauthClientDetails;
import com.example.authorizationserver.domain.OauthClientDetailsRepository;
import com.example.authorizationserver.domain.User;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserService {

  private final UserRepository userRepository;
  private final OauthClientDetailsRepository clientRepository;
  private final PasswordEncoder passwordEncoder;

  @Transactional
  public User registerUser(String username, String password) {
    User user = new User();
    user.setUsername(username);
    user.setPassword(passwordEncoder.encode(password));
    user.setEnabled(true);
    // Set roles as needed
    return userRepository.save(user);
  }

  @Transactional
  public ResponseEntity<String> registerClient(String clientId, String clientSecret, String authorizedGrantTypes, String scopes) {
    Optional<OauthClientDetails> opClient = clientRepository.findById(clientId);
    if(opClient.isPresent()){

      log.error("Already exist client : {}", clientId);
      return new ResponseEntity<>("유저가 이미 존재합니다.", HttpStatus.BAD_REQUEST);
    }else{
      OauthClientDetails client = OauthClientDetails.builder()
                                          .client_id(clientId)
                                          .client_secret(passwordEncoder.encode(clientSecret))
                                          .authorized_grant_types(authorizedGrantTypes)
                                          .scope(scopes)
                                          .role("ROLE_CLIENT")
                                          .build();
      clientRepository.save(client);
      log.info("client 생성 완료 : {}", client.toString());
      return new ResponseEntity<>(" 유저 생성 완료 : "+ clientId, HttpStatus.OK);
    }
}
}
