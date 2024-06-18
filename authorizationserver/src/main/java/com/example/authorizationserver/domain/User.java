package com.example.authorizationserver.domain;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Entity
public class User implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name="user_id")
    private Long id;

    private String username;
    private String password;
    private boolean enabled;
    private String role;
    // @ManyToMany(fetch = FetchType.EAGER)
    // @JoinTable(
    //     name = "user_role",
    //     joinColumns = @JoinColumn(name = "user_id"),
    //     inverseJoinColumns = @JoinColumn(name = "role_id")
    // )
    // private Set<Role> roles;

}
