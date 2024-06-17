package com.example.authorizationserver.config;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class GlobalExceptionHandler {

  @ExceptionHandler(CustomException.class)
  protected ResponseEntity<ErrorResponse> customErrorsException(CustomException ex){
    StackTraceElement[] stackTraceElement = ex.getStackTrace();
    StringBuffer sb = new StringBuffer();
    sb.append("[handleCustomException] - ");
    sb.append(ex.getHTTP_STATUS());
    sb.append("  ");
    sb.append(ex.getMessage());
    for (StackTraceElement ste : stackTraceElement) {
        if (ste.toString().contains("authorizationserver")) {
            sb.append(ste);
            break;
        }
    }

    log.error("{}: {}", HttpStatus.BAD_REQUEST, sb);
    final ErrorResponse response = ErrorResponse.of(ex.getHTTP_STATUS().value(), ex.getMESSAGE());
    return new ResponseEntity<>(response, ex.getHTTP_STATUS());
  }
}
