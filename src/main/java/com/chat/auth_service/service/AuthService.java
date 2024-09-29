package com.chat.auth_service.service;

import com.chat.auth_service.server.model.*;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface AuthService {
  Mono<ResponseEntity<Login200Response>> login(Mono<LoginRequest> loginRequest, String requestId);

  Mono<ResponseEntity<CommonResponse>> register(Mono<RegisterRequest> registerRequest, String requestId);

  Mono<ResponseEntity<RefreshToken200Response>> refreshToken(
          Mono<RefreshTokenRequest> refreshTokenRequest, String requestId);

  Mono<ResponseEntity<CommonResponse>> forgotPassword(
          Mono<ForgotPasswordRequest> forgotPasswordRequest, String requestId);

  Mono<ResponseEntity<CommonResponse>> resetPassword(
          Mono<ResetPasswordRequest> resetPasswordRequest, String requestId);

  Mono<ResponseEntity<CommonResponse>> changePassword(
      Mono<ChangePasswordRequest> changePasswordRequest, String requestId, UUID userId);
}
