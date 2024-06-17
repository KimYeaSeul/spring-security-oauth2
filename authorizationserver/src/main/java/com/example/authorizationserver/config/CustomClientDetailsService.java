package com.example.authorizationserver.config;

import java.util.Arrays;
import java.util.Optional;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Service;

import com.example.authorizationserver.domain.Client;
import com.example.authorizationserver.domain.ClientRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CustomClientDetailsService implements ClientDetailsService {

  private final ClientRepository clientRepository;

  @Override
  public ClientDetails loadClientByClientId(String clientId) {
    System.out.println("클라이언트 디텡틸즈 들어왔다");
      Optional<Client> opClient = clientRepository.findById(clientId);
      if (opClient.isEmpty()) {
          throw new UsernameNotFoundException("loadClientByClientId  Client not found!!!!!!!!!");
      }
      Client client = opClient.get();
      BaseClientDetails clientDetails = new BaseClientDetails();
      clientDetails.setClientId(client.getClient_id());
      clientDetails.setClientSecret(client.getClient_secret());
      clientDetails.setAuthorizedGrantTypes(Arrays.asList(client.getAuthorities().split(",")));
      clientDetails.setScope(Arrays.asList(client.getScope().split(",")));
      return clientDetails;
  }
}
