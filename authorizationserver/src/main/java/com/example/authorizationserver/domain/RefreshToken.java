package com.example.authorizationserver.domain;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "oauth_refresh_token")
public class RefreshToken implements Serializable {

  @Id
  public String tokenId;
  public String token;
  @Column(name="authentication")
  public String auth;

  public void updateAccessToken(String accessToken) {
    this.token = accessToken;
  }
}
