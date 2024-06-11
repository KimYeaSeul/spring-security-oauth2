package com.example.authorizationserver.config;

import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.example.authorizationserver.domain.PrincipalDetails;
import com.example.authorizationserver.domain.TokenInfoDto;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class JwtTokenProvider {

  private SecretKey secretkey;
  private static final long ACCESS_TOKEN_EXPIRE_TIME = 1000 * 60 * 30L; // 30분
  // private static final long REFRESH_TOKEN_EXPIRE_TIME = 1000 * 60 * 60L * 24 * 7; // 1주
  // private static final String KEY_ROLE = "role";

  public JwtTokenProvider(@Value("${jwt.secret}") String key){
    this.secretkey = Keys.hmacShaKeyFor(key.getBytes());
  }

  public TokenInfoDto generateAccessToken(Authentication authentication) {
    String accessToken = generateToken(authentication);
    return TokenInfoDto.builder()
            .grantType("Bearer")
            .accessToken(accessToken)
            .build();
    //  generateToken(authentication, ACCESS_TOKEN_EXPIRE_TIME);
  }

  // 1. refresh token 발급
//   public void generateRefreshToken(Authentication authentication, String accessToken) {
//     String refreshToken = generateToken(authentication, REFRESH_TOKEN_EXPIRE_TIME);
//     tokenService.saveOrUpdate(authentication.getName(), refreshToken, accessToken);
//   }

  /**
   * [JWT 생성]
   * User 정보를 통해 AccessToken 생성
   * @param Authentication 인증 정보 객체
   * @return TokenInfo
   */
  public String generateToken(Authentication authentication){
    // 권한 가져오기
    String authorities = authentication.getAuthorities().stream()
                      .map(GrantedAuthority::getAuthority)
                      .collect(Collectors.joining(","));
                      // TODO : grant_type 에 따른 응답값을 보고 오류를 수정하시오!!
    log.info("authentication.getPrincipal() : {}",authentication.getPrincipal().toString());
    PrincipalDetails userDetails = (PrincipalDetails)authentication.getPrincipal();
    Long userId = userDetails.getUser().getId();
    String username = userDetails.getUsername();

    Date now = new Date();

    // Access Token 생성
    Date accessTokenExpiresIn = new Date(now.getTime() + ACCESS_TOKEN_EXPIRE_TIME);
    return Jwts.builder()
              .subject(authentication.getName())
              .issuedAt(now)
              .claim("userId", userId)
              .claim("username", username)
              .claim("auth", authorities)
              .expiration(accessTokenExpiresIn)
              .signWith(secretkey)
              .compact();

    // return TokenInfoDto.builder()
    //           .grantType("Bearer")
    //           .accessToken(accessToken)
    //           .build();
  }

  // 3. accessToken 재발급
  // public String reissueAccessToken(String accessToken) throws Exception {
  //   if (StringUtils.hasText(accessToken)) {
  //       Token token = tokenService.findByAccessTokenOrThrow(accessToken);
  //       String refreshToken = token.getRefreshToken();

  //       if (validateToken(refreshToken)) {
  //           String reissueAccessToken = generateAccessToken(getAuthentication(refreshToken));
  //           tokenService.updateToken(reissueAccessToken, token);
  //           return reissueAccessToken;
  //       }
  //   }
  //   return null;
  // } 

public boolean validateToken(String token) throws Exception {
  if (!StringUtils.hasText(token)) {
      return false;
  }

  Claims claims = parseClaims(token);
  log.info("=== subject :{} ========", claims.getSubject());
  return claims.getExpiration().after(new Date());
}


  /**
   * [JWT 복호화]
   * JWT를 복화하하여 토큰에 들어있는 정보를 반환
   * @param String accessToken
   * @return Authentication
   */
  public Authentication getAuthentication(String accessToken) throws Exception{
    // 토큰 복호화
    Claims claims = parseClaims(accessToken);
    if(claims.get("auth") == null){
      throw new RuntimeException("권한 정보가 없는 토큰입니다.");
    }
    List<SimpleGrantedAuthority> authorities = getAuthorities(claims);

    // 2. security의 User 객체 생성
    User principal = new User(claims.getSubject(), "", authorities);
    return new UsernamePasswordAuthenticationToken(principal, accessToken, authorities);
  }

  /**
   * 권한 추출
   * @param Claims claims
   * @return List<SimpleGrantedAuthority>
   * @throws Exception
   */
  private List<SimpleGrantedAuthority> getAuthorities(Claims claims){
    return Arrays.stream(claims.get("auth").toString().split(","))
            .map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    // return Collections.singletonList(new SimpleGrantedAuthority(claims.get(KEY_ROLE).toString()));
  }
// 토큰에서 Email을 추출한다.
  public String getUid(String token) {
    return Jwts.parser().verifyWith(secretkey).build().parseSignedClaims(token).getPayload().getSubject();
  }

  /**
   * [JWT Claim 추출]
   * JWT 토큰 안의 Claim 정보를 추출
   * @param String accessToken
   * @return Claims
   * @throws Exception 
   */
  private Claims parseClaims(String accessToken){
    log.info("parseClaims : {} " ,accessToken); // Base64(common:1234) = Basic Y29tbW9uOjEyMzQ=
    try{
      return Jwts.parser().verifyWith(secretkey).build().parseSignedClaims(accessToken).getPayload();
    } catch (ExpiredJwtException e){
      return e.getClaims();
    } catch (MalformedJwtException e){
      log.info("MalformedJwtException : InValid Access Token");
      // throw new Exception("InValid Access Token");
    } catch (SecurityException e){
      log.info("SecurityException : InValid Access Token");
      // throw new Exception("InValid JWT Signature");
    }
    return null;
  }
}
