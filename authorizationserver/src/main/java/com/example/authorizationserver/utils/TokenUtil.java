package com.example.authorizationserver.utils;

import com.example.authorizationserver.custom.CustomUserDetails;
import com.example.authorizationserver.custom.CustomUserDetailsService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecureDigestAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class TokenUtil {


    private SecretKey secretkey;
    private PrivateKey privateKey;
    private static final long ACCESS_TOKEN_EXPIRE_TIME = 1000 * 60 * 30L; // 30분
    private static final long REFRESH_TOKEN_EXPIRE_TIME = 1000 * 60 * 60L * 24 * 7; // 1주
    private static final String KEY_ROLE = "auth";

    // JWT 형식 검사 정규식 패턴
    private static final Pattern JWT_PATTERN = Pattern.compile("^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$");
    private final CustomUserDetailsService userDetailsService;

//      public TokenUtil(@Value("${jwt.secret}") String key,CustomUserDetailsService userDetailsService) throws Exception{
//        this.secretkey = Keys.hmacShaKeyFor(key.getBytes());
//        this.userDetailsService = userDetailsService;
//
//        String path = "/home/kys912/development/spring-security-oauth2/authorizationserver/src/main/resources";
//          String privateKeyContent = new String(Files.readAllBytes(Paths.get(path, "private_key.pem")));
//          privateKeyContent = privateKeyContent
//                  .replace("-----BEGIN PRIVATE KEY-----", "")
//                  .replace("-----END PRIVATE KEY-----", "")
//                  .replaceAll("\\s", "");
//
//          PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
//          KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//          this.privateKey = keyFactory.generatePrivate(keySpec);
//      }

    // access token 생성
    public String generateAccessToken(Authentication authentication) {
        Map<String,Object> claims = new HashMap<>();

        CustomUserDetails userDetails = (CustomUserDetails)authentication.getPrincipal();
        Long userId = userDetails.getUser().getId();
        String username = userDetails.getUsername();

        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        claims.put("userId", userId);
        claims.put("username", username);
        claims.put("auth", authorities);

        return generateToken(authentication.getName(), claims, ACCESS_TOKEN_EXPIRE_TIME);
    }

    // refresh token 생성
    public OAuth2RefreshToken generateRefreshToken(OAuth2Authentication authentication) {
        String token = generateToken(authentication.getName(), new HashMap<>(), REFRESH_TOKEN_EXPIRE_TIME);
        return new DefaultOAuth2RefreshToken(token);
    }

    /**
     * [JWT 생성]
     * User 정보를 통해 AccessToken 생성
     * @param subject 인증 주체 랄까
     * @param claims claims
     * @param expiration 만료 시간
     * @return TokenInfo
     */
    private String generateToken(String subject, Map<String,Object> claims, long expiration ){

        log.info("========== generateToken  ==========");

        // Token 생성
        Date now = new Date();
        Date tokenExpiresDate = new Date(now.getTime() + expiration);

        return Jwts.builder()
                .subject(subject)
                .issuedAt(now)
                .claims(claims)
                .expiration(tokenExpiresDate)
                .signWith(secretkey)
                .compact();
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

    public String resolveToken(HttpServletRequest request) {

        log.info("========== resolveToken  ==========");
        String bearerToken = request.getHeader("Authorization");
        log.info("get header {} ", bearerToken);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public boolean validateToken(String token){
        log.info("========== validateToken  ==========");
        if (!StringUtils.hasText(token)) {
            return false;
        }
        Claims claims = parseClaims(token);
        log.info("=== validateToken subject :{} ========", claims.getSubject());
        return claims.getExpiration().after(new Date());
    }

    public boolean isJwtToken(String token) {
        // JWT 형식인지 확인
        if (!JWT_PATTERN.matcher(token).matches()) {
            return false;
        }

        // 각 부분을 분할
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return false;
        }

        // Base64로 디코딩 시도
        try {
            Base64.getUrlDecoder().decode(parts[0]);
            Base64.getUrlDecoder().decode(parts[1]);
            // Signature 부분은 디코딩하지 않음
        } catch (IllegalArgumentException e) {
            return false;
        }

        return true;
    }
    /**
     * [JWT 복호화]
     * JWT를 복화하하여 토큰에 들어있는 정보를 반환
     * @param accessToken token
     * @return Authentication
     */
    public Authentication getAuthentication(String accessToken) {
        log.info("========== getAuthentication  ==========");
        // 토큰 복호화
        Claims claims = parseClaims(accessToken);
        if(claims.get(KEY_ROLE) == null){
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }
        // List<SimpleGrantedAuthority> authorities = getAuthorities(claims);

        // 2. security의 User 객체 생성
        UserDetails principal = userDetailsService.loadUserByUsername(getUid(accessToken));
        log.info("principal = {} " ,principal.toString());
        log.info("claims.get(auth) = {} ",claims.get("auth"));
        return new UsernamePasswordAuthenticationToken(principal, "", principal.getAuthorities());
    }

    /**
     * 권한 추출
     * @param claims 권한 목록
     * @return List<SimpleGrantedAuthority>
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
     * @param accessToken token
     * @return Claims
     */
    private Claims parseClaims(String accessToken){
        log.info("parseClaims : {} " ,accessToken); // Base64(common:1234) = Basic Y29tbW9uOjEyMzQ=
        try{
            return Jwts.parser().verifyWith(secretkey).build().parseSignedClaims(accessToken).getPayload();
        } catch (ExpiredJwtException e){
            log.info("ExpiredJwtException : Expired Access Token");
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

    public Map<String, Object> getClaims() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken) {
            JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) authentication;
            return jwtAuthenticationToken.getTokenAttributes();
        }
        throw new IllegalStateException("Authentication is not of type JwtAuthenticationToken");
    }
}
