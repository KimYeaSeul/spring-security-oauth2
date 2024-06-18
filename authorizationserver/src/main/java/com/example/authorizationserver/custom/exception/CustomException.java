package com.example.authorizationserver.custom.exception;

import org.springframework.http.HttpStatus;

import lombok.Getter;

@Getter
public class CustomException extends RuntimeException{
  public HttpStatus HTTP_STATUS;
  public String MESSAGE;

  public CustomException(){}

  public CustomException(HttpStatus status, String msg){
    this.HTTP_STATUS = status;
    this.MESSAGE = msg;
  }
}
