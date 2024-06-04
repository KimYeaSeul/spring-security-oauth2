package com.example.authorizationserver.filter;

import java.io.IOException;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.authorizationserver.config.JwtTokenProvider;
import com.example.authorizationserver.domain.User;
import com.example.authorizationserver.user.UserRepository;

import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

  private final JwtTokenProvider jwtUtil;
  private final UserRepository userRepository;


  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    log.info("필터 돌아요~");
      // request Header에서 AccessToken을 가져온다.
      String atc = request.getHeader("Authorization");

      // 토큰 검사 생략(모두 허용 URL의 경우 토큰 검사 통과)
      if (!StringUtils.hasText(atc)) {
          doFilter(request, response, filterChain);
          return;
      }

      // AccessToken을 검증하고, 만료되었을경우 예외를 발생시킨다.
      try {
        if (!jwtUtil.validateToken(atc)) {
            throw new JwtException("Access Token 만료!");
        }
      } catch (Exception e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
      }

      // AccessToken의 값이 있고, 유효한 경우에 진행한다.
      try {
        if (jwtUtil.validateToken(atc)) {

            // AccessToken 내부의 payload에 있는 email로 user를 조회한다. 없다면 예외를 발생시킨다 -> 정상 케이스가 아님
            User findUser = userRepository.findByUsername(jwtUtil.getUid(atc))
                    .orElseThrow(IllegalStateException::new);

            // SecurityContext에 인증 객체를 등록해준다.
            Authentication auth = getAuthentication(findUser);
            log.info(auth.getName());
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
      } catch (Exception e) {
        e.printStackTrace();
      }

      filterChain.doFilter(request, response);
  }



  public Authentication getAuthentication(User member) {
    return new UsernamePasswordAuthenticationToken(member, "", List.of(new SimpleGrantedAuthority(member.getRoles().toString())));
  }

}
