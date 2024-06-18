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
@Table(name = "oauth_access_token")
public class AccessToken implements Serializable {

    @Id
    @Column(name="authentication_id")
    public String authId;
    public String tokenId;
    public String token;
    public String userName;
    public String clientId;
    public String authentication;
    public String refreshToken;
}