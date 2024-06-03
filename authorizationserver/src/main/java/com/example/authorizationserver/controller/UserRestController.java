package com.example.authorizationserver.controller;

import java.util.Map;
import java.util.Optional;

import javax.transaction.Transactional;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.authorizationserver.domain.OauthClientDetails;
import com.example.authorizationserver.domain.OauthClientDetailsRepository;
import com.example.authorizationserver.domain.User;
import com.example.authorizationserver.domain.UserService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
@Slf4j
@RestController
@RequiredArgsConstructor
public class UserRestController {
  private final OauthClientDetailsRepository oauthClientDetailsRepository;
  private final PasswordEncoder passwordEncoder;
  private final UserService userService;

  @GetMapping("/oauth2/test")
  public String test(){
    return "Welcome to test page";
  }
  @Transactional
  @PostMapping("/oauth2/client/join")
  public ResponseEntity<String> registerClient(@RequestParam Map<String,String> client){
    log.info("여기 들어옴"+client.get("clientId"));
    // if(!client.validDto()){
    //   log.warn("Join Parameters : {}", client.toString() );
    //   return new ResponseEntity<>(" 파라미터를 정확하게 작성해주세요.", HttpStatus.BAD_REQUEST);
    // }
    Optional<OauthClientDetails> opClient = oauthClientDetailsRepository.findById(client.get("clientId"));
    if(!opClient.isPresent()){
      String rawSecret = client.get("secret");
      String encSecret = passwordEncoder.encode(rawSecret);
      OauthClientDetails joinClient = OauthClientDetails.builder()
                                        .client_id(client.get("clientId")).client_secret(encSecret)
                                        .authorized_grant_types(client.get("type")).scope(client.get("scope"))
                                        .role("ROLE_CLIENT").build();
      oauthClientDetailsRepository.save(joinClient);
      log.info("Completely Create User : {}", joinClient.toString());
      return new ResponseEntity<>(" 유저 생성 완료 : "+ joinClient.getClient_id(), HttpStatus.OK);
    }else{
      log.info("Already exist client : {}", client.get("clientId"));
      return new ResponseEntity<>("유저가 이미 존재합니다.", HttpStatus.BAD_REQUEST);
    }
  }

  // @PreAuthorize("hasAuthority('ROLE_CLIENT')") // 특정 권한을 요구
  @PostMapping("/oauth2/user/join")
  public User registerUser(@RequestParam String username, @RequestParam String password, Authentication authentication) {
    log.info("user join ");
    // 인증된 클라이언트 확인 (Optional)
    // String clientId = authentication.getName();
    // System.out.println("Authenticated Client ID: " + clientId);
      return userService.registerUser(username, password);
  }
}