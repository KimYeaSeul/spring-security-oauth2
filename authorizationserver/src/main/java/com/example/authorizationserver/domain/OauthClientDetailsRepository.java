package com.example.authorizationserver.domain;

import org.springframework.data.jpa.repository.JpaRepository;

public interface OauthClientDetailsRepository extends JpaRepository<OauthClientDetails,String> {

}

