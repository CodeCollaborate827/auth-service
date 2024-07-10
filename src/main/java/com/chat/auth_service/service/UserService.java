package com.chat.auth_service.service;

import com.chat.auth_service.server.model.Login200Response;
import com.chat.auth_service.server.model.LoginRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public interface UserService {
    Mono<ResponseEntity<Login200Response>> login(Mono<LoginRequest> loginRequest);
}
