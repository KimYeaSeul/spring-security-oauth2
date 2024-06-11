package com.example.authorizationserver.user;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.authorizationserver.domain.User;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
@Slf4j
@RestController
@RequiredArgsConstructor
public class UserRestController {
  private final UserService userService;

  @GetMapping("/oauth2/test")
  public String test(){
    return "Welcome to test page";
  }
  @PostMapping("/oauth2/client/join")
  public ResponseEntity<String> registerClient(@RequestParam Map<String,String> client){
    log.info("[registerClient] {}",client.get("client_id"));
    // if(!client.validDto()){
    //   log.warn("Join Parameters : {}", client.toString() );
    //   return new ResponseEntity<>(" 파라미터를 정확하게 작성해주세요.", HttpStatus.BAD_REQUEST);
    // }
    
    return userService.registerClient(client.get("client_id"),client.get("client_secret"),client.get("type"),client.get("scope"));
  }

  // @PreAuthorize("hasAuthority('ROLE_CLIENT')") // 특정 권한을 요구
  @PostMapping("/oauth2/user/join")
  public User registerUser(@RequestParam String username, @RequestParam String password, Authentication authentication) {
    log.info("[registerUser] {}", username);
    // 인증된 클라이언트 확인 (Optional)
    if(authentication != null && authentication.isAuthenticated()){
      log.info("인증 Client Id = {}", authentication.getName());
    }
      return userService.registerUser(username, password);
  }
}