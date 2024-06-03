package com.example.authorizationserver.utils;

import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Base64;

import com.google.common.hash.Hashing;
/*
 * https://aday7.tistory.com/entry/Java-%ED%8C%A8%EC%8A%A4%EC%9B%8C%EB%93%9C-%EC%95%94%ED%98%B8%ED%99%94-SHA-%EC%A0%81%EC%9A%A9-%EC%98%88%EC%A0%9C-SHA-256-with-Salt
 */
public class ShaUtils {

  
  private static final SecureRandom random = new SecureRandom();
  public static String getSalt(){
    byte[] salt = new byte[16];
    random.nextBytes(salt);
    return Base64.getEncoder().encodeToString(salt);
  }

  public static String sha256WithSaltEncode(String plainTxt, String salt){
    return Hashing.sha256()
            .hashString(plainTxt + salt, Charset.forName("UTF-8"))
            .toString();
  }
}
