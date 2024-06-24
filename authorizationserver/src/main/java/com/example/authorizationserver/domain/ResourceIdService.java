package com.example.authorizationserver.domain;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ResourceIdService {

    private final ClientRepository clientRepository;

    public String getResourceIdForClient(String clientId) {
        System.out.println("여기 작동 했나요?");
        return clientRepository.findResourceIdByClientId(clientId);
    }
}
