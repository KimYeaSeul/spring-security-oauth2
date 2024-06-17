package com.example.authorizationserver.config;

import org.springframework.http.HttpStatus;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CustomException extends RuntimeException{
  public HttpStatus HTTP_STATUS;
  public String MESSAGE;
}
