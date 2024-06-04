package com.example.authorizationserver.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TokenInfoDto {

  /*
   * 클라이언트에게 반환할 JWT 정보
   */
  private String grantType;
  private String accessToken;
}
