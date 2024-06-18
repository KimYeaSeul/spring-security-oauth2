package com.example.authorizationserver.domain;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.authorizationserver.custom.exception.CustomException;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
@Slf4j
@RestController
@RequiredArgsConstructor
public class UserRestController {
  private final UserService userService;

  // Client 생성 시 보안을 위해 설정
  // TODO : 바꾸세요
  @Value("${client.join.key}")
  private String secretKey;

  @GetMapping("/oauth/test")
  public String test(){
    return "Welcome to test page";
  }

  @PostMapping("/oauth/client/join")
  public ResponseEntity<String> registerClient( @RequestParam String client_id,
                                                @RequestParam String client_secret,
                                                @RequestHeader("Authorization") String code )
  {
//    log.debug("[registerClient] {}, code = {}",client_id, code);
    if(code != null && code.equals(secretKey)){
      String id = userService.registerClient(client_id, client_secret);
      return new ResponseEntity<>("클라이언트 생성 완료 : "+ id, HttpStatus.OK);
    }
//    return new ResponseEntity<>("클라이언트 생성 완료 : ", HttpStatus.OK);
    throw new CustomException(HttpStatus.BAD_REQUEST, "클라이언트 생성 실패 - Code Error");
  }

  @PostMapping("/oauth/user/join")
  @PreAuthorize("hasRole('CLIENT')")
  public ResponseEntity<String> registerUser( @RequestParam String username,
                                              @RequestParam String password,
                                              Authentication authentication ) 
  {
    log.info("[registerUser] {}", username);
    if(authentication != null && authentication.isAuthenticated()){
      log.info("Client = {}", authentication.getName());
      String id = userService.registerUser(username, password);
      return new ResponseEntity<>("유저 생성 완료 : "+ id, HttpStatus.OK);
    }
    throw new CustomException(HttpStatus.BAD_REQUEST, "유저 생성 실패 - 인증되지 않은 클라이언트");
  }
}