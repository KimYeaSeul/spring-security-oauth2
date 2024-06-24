package com.example.authorizationserver.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.example.authorizationserver.utils.TokenUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
//@Component
public class AuthFilter{
//        extends OncePerRequestFilter {

  // 여기는 어떤 인증 형태든 무조건 확인함
  private final TokenUtil tokenUtil;
  private final JdbcTokenStore tokenStore;

//  @Override
//  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//      log.info(" AuthFilter 필터 돌아요~");
//      String token = tokenUtil.resolveToken(request);
//        log.info("return token = {}", token);
//    // jwt 인지 확인해서 토큰 형태에 따라 validation 함수 돌려가지고오오오오오오오오오오해보자고오오오오오오오
//
//      if(token != null){
//        if( tokenUtil.isJwtToken(token) && tokenUtil.validateToken(token) ){
//            log.info("안녕 난 password 타입이야!");
//            Authentication auth = tokenUtil.getAuthentication(token);
//            SecurityContextHolder.getContext().setAuthentication(auth);
//        }
//        else{
//            OAuth2AccessToken auth = tokenStore.readAccessToken(token);
//            log.info("안녕 난 client credentials 타입이야 토큰 타입은 {} 이지!", auth.getTokenType());
//            log.info("안녕 난 client credentials 타입이야 토큰 getExpiresIn은 {} 지!", auth.getExpiresIn());
//            log.info("안녕 난 client credentials 타입이야 토큰 isExpired는 {} 지!", auth.isExpired());
//            log.info("안녕 난 client credentials 타입이야 토큰은 {} 지!", auth.getValue());
//          // expired 를 확인해서 setAuytnehtication 할 필요가 없지 않나..?
//          // 이미 set 되어있는거를 가져온거 아닌가?..
//        }
//      }
//      filterChain.doFilter(request, response);
//  }
}
