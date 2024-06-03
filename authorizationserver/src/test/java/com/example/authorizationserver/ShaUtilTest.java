package com.example.authorizationserver;

import org.junit.jupiter.api.Test;

import com.example.authorizationserver.utils.ShaUtils;

public class ShaUtilTest {

  String plainPassword = "Aasegfg12test@";

  @Test
  void testSha256(){
    for(int i=0; i<5; i++){
      String hashData = ShaUtils.sha256WithSaltEncode(plainPassword,ShaUtils.getSalt());
      System.out.println("Salt 적용 데이터 = "+ hashData);
    }
  }
}
