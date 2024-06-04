package com.example.authorizationserver.domain;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Builder
@Table(name = "oauth_client_details")
public class OauthClientDetails {
  @Id
  @Column(unique = true)
  String client_id;
  String resource_ids;
  String client_secret;
  String scope;
  String role;
  String authorized_grant_types;
  String web_server_redirect_uri;
  String authorities;
  Integer access_token_validity;
  Integer refresh_token_validity;
  @Column(name="additional_information")
  String audience;
  String autoapprove;
}
