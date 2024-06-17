package com.example.authorizationserver.config;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class ErrorResponse {
  private int status;                 // 에러 상태 코드
  private String resultMsg;           // 에러 메시지

  @Builder
  protected ErrorResponse(final int status, final String reason) {
      this.status = status;
      this.resultMsg = reason;
  }

  public static ErrorResponse of(final int status, final String reason) {
    return new ErrorResponse(status, reason);
  }
}
