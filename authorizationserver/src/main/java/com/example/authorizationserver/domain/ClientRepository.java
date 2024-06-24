package com.example.authorizationserver.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ClientRepository extends JpaRepository<Client,String> {

    @Query(nativeQuery = true, value = "SELECT resource_ids FROM oauth_client_details WHERE client_id = :clientId")
    String findResourceIdByClientId(@Param("clientId") String clientId);
}

