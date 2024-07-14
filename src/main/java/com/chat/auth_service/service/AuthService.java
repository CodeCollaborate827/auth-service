package com.chat.auth_service.service;

import com.chat.auth_service.server.model.*;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;

public interface AuthService {
  Mono<ResponseEntity<Login200Response>> login(Mono<LoginRequest> loginRequest);

  Mono<ResponseEntity<Register200Response>> register(Mono<RegisterRequest> registerRequest);

  Mono<ResponseEntity<CommonResponse>> rendSendVerificationEmail(
      Mono<ResendVerificationEmailRequest> resendVerificationEmailRequest);
}
