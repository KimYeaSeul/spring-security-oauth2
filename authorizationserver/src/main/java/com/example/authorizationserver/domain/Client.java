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
public class Client {
  @Id
  @Column(unique = true)
  private String client_id;
  private String resource_ids;
  private String client_secret;
  private String scope;
  private String role;
  private String authorized_grant_types;
  private String web_server_redirect_uri;
  private String authorities;
  private Integer access_token_validity;
  private Integer refresh_token_validity;
  @Column(name="additional_information")
  private String audience;
  private String autoapprove;
}
