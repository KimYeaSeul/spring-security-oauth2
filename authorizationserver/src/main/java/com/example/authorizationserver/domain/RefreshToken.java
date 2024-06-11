package com.example.authorizationserver.domain;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class RefreshToken implements Serializable {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name="token_id")
  public Long tokenId;
  public String email;
  @Column(name="access_token")
  public String accessToken;
  @Column(name="refresh_token")
  public String refreshToken;

  public void updateAccessToken(String accessToken) {
    this.accessToken = accessToken;
  }
}
