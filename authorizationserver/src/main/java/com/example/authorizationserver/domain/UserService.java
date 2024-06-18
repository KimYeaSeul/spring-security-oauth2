package com.example.authorizationserver.domain;

import java.util.Optional;

import javax.transaction.Transactional;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.authorizationserver.custom.exception.CustomException;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserService {

  private final PasswordEncoder encoder;
  private final UserRepository userRepository;
  private final ClientRepository clientRepository;

  private final String GRANT_TYPES = "password,client_credentials,refresh_token";

  @Transactional
  public String registerClient(String client_id, String secret) {

    Optional<Client> opClient = clientRepository.findById(client_id);
    if(opClient.isPresent()){
      log.error("Already exist client : {}", client_id);
      throw new CustomException(HttpStatus.BAD_REQUEST, "존재하는 클라이언트 입니다.");
    }else{
      // TODO : accessTokenValidation time
      Client client = Client.builder()
                        .client_id(client_id)
                        .client_secret(encoder.encode(secret))
                        .authorized_grant_types(GRANT_TYPES)
                        .scope("read,write")
                        .role("CLIENT")
                        .build();
      clientRepository.save(client);
      log.info("클라이언트 생성 완료 : {}", client.toString());
      return  client_id;
    }
  }

  @Transactional
  public String registerUser(String username, String password) {

    Optional<User> opUser = userRepository.findByUsername(username);
    if(opUser.isPresent()){
      log.error("Already exist user : {}", username);
      throw new CustomException(HttpStatus.BAD_REQUEST, "존재하는 유저 입니다.");
    }else{
      User user = User.builder()
                    .username(username)
                    .password(encoder.encode(password))
                    .role("USER")
                    .enabled(true)
                    .build();
      userRepository.save(user);
      log.info("유저 생성 완료 : {}", user.toString());
      return username;
    }
  }
}
