package com.example.authorizationserver.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.authorizationserver.config.JwtTokenProvider;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

  // 여기는 어떤 인증 형태든 무조건 돌아
  private final JwtTokenProvider jwtTokenProvider;
  private final JdbcTokenStore tokenStore;
  // private final TokenUtil tokenUtil;
  // private final UserRepository userRepository;


  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
      log.info(" JwtAuthFilter 필터 돌아요~");
      String token = jwtTokenProvider.resolveToken(request);

// jwt 인지 확인해서 토큰 형태에 따라 validation 함수 돌려가지고오오오오오오오오오오해보자고오오오오오오오

      if(token != null){
        if( jwtTokenProvider.isJwtToken(token) && jwtTokenProvider.validateToken(token) ){
          Authentication auth = jwtTokenProvider.getAuthentication(token);
          SecurityContextHolder.getContext().setAuthentication(auth);
        }
        else{
          OAuth2AccessToken auth = tokenStore.readAccessToken(token);
          log.info("안녕 난 client credentials 타입이야 토큰 타입은 {} 이지!", auth.getTokenType());
          log.info("안녕 난 client credentials 타입이야 토큰 getExpiresIn은 {} 지!", auth.getExpiresIn());
          log.info("안녕 난 client credentials 타입이야 토큰 isExpired는 {} 지!", auth.isExpired());
          log.info("안녕 난 client credentials 타입이야 토큰은 {} 지!", auth.getValue());
          // expired 를 확인해서 setAuytnehtication 할 필요가 없지 않나..?
          // 이미 set 되어있는거를 가져온거 아닌가?..
        }
      }
      // try {
      //     if( token != null && jwtTokenProvider.validateToken(token) ){
      //       Authentication auth = jwtTokenProvider.getAuthentication(token);
      //       SecurityContextHolder.getContext().setAuthentication(auth);
      //     }
      // } catch (Exception e) {
      //   // TODO Auto-generated catch block
      //   log.info("무슨 에러 일까나");
      //   e.printStackTrace();
      // }
      filterChain.doFilter(request, response);
  //     // request Header에서 AccessToken을 가져온다.
  //     String atc = request.getHeader("Authorization");
  //     log.info("Authorication = {}", atc);
  //     // beaer 이면 토큰 유효성 검사를 하고, basic 이면 안하면 되는거 아녀?
  //     // 토큰 검사 생략(모두 허용 URL의 경우 토큰 검사 통과)
  //     if (!StringUtils.hasText(atc)) {
  //         doFilter(request, response, filterChain);
  //         return;
  //     }

  //     // AccessToken을 검증하고, 만료되었을경우 예외를 발생시킨다.
  //     if(!atc.startsWith("Basic")){
  //       try {
  //         if (!jwtUtil.validateToken(atc)) {
  //             throw new JwtException("Access Token 만료!");
  //         }
  //       } catch (Exception e) {
  //         e.printStackTrace();
  //       }

  //       // AccessToken의 값이 있고, 유효한 경우에 진행한다.
  //       try {
  //         if (jwtUtil.validateToken(atc)) {

  //             // AccessToken 내부의 payload에 있는 email로 user를 조회한다. 없다면 예외를 발생시킨다 -> 정상 케이스가 아님
  //             User findUser = userRepository.findByUsername(jwtUtil.getUid(atc))
  //                     .orElseThrow(IllegalStateException::new);

  //             // SecurityContext에 인증 객체를 등록해준다.
  //             Authentication auth = getAuthentication(findUser);
  //             log.info(auth.getName());
  //             SecurityContextHolder.getContext().setAuthentication(auth);
  //         }
  //       } catch (Exception e) {
  //         e.printStackTrace();
  //       }
  //     }

  //     filterChain.doFilter(request, response);
  }
}
