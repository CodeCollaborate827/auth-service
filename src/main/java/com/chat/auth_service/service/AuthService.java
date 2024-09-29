package com.chat.auth_service.service;

import com.chat.auth_service.server.model.*;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;

public interface AuthService {
  Mono<ResponseEntity<Login200Response>> login(Mono<LoginRequest> loginRequest);

  Mono<ResponseEntity<CommonResponse>> register(Mono<RegisterRequest> registerRequest);

  Mono<ResponseEntity<RefreshToken200Response>> refreshToken(
      Mono<RefreshTokenRequest> refreshTokenRequest);

  Mono<ResponseEntity<CommonResponse>> forgotPassword(
      Mono<ForgotPasswordRequest> forgotPasswordRequest);

  Mono<ResponseEntity<CommonResponse>> resetPassword(
      Mono<ResetPasswordRequest> resetPasswordRequest);
}
