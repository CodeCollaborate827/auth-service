package com.chat.auth_service.service;

import com.chat.auth_service.server.model.Login200Response;
import com.chat.auth_service.server.model.LoginRequest;
import com.chat.auth_service.server.model.Register200Response;
import com.chat.auth_service.server.model.RegisterRequest;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;

public interface AuthService {
    Mono<ResponseEntity<Login200Response>> login(Mono<LoginRequest> loginRequest);
    Mono<ResponseEntity<Register200Response>> register(Mono<RegisterRequest> registerRequest);
}
