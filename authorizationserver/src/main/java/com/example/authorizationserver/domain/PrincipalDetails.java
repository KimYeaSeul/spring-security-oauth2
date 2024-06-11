package com.example.authorizationserver.domain;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.Data;

@Data
public class PrincipalDetails implements UserDetails{

  public User user;
  public PrincipalDetails(User user){
    this.user = user;
  }

  @Override
  public Collection<GrantedAuthority> getAuthorities() {
    // Collection<GrantedAuthority> collection = new ArrayList<>();
    //     collection.add(new GrantedAuthority() {
    //         @Override
    //         public String getAuthority() {
    //             System.out.println("권환 이리 와보슈 "+ user.getRoles());
    //             return String.valueOf(user.getRoles());
    //         }
    //     });
      return user.getRoles().stream()
      .map(role -> (GrantedAuthority) () -> "ROLE_" + role.getName())
      .collect(Collectors.toList());
  }

  @Override
  public String getPassword() {
    return user.getPassword();
  }

  @Override
  public String getUsername() {
    return user.getUsername();
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }

}
