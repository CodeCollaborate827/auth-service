package com.chat.auth_service.service;

import com.chat.auth_service.server.model.*;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.multipart.Part;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface AuthService {
  Mono<ResponseEntity<Login200Response>> login(Mono<LoginRequest> loginRequest);

  Mono<ResponseEntity<RefreshToken200Response>> refreshToken(
      Mono<RefreshTokenRequest> refreshTokenRequest);

  Mono<ResponseEntity<CommonResponse>> forgotPassword(
      Mono<ForgotPasswordRequest> forgotPasswordRequest);

  Mono<ResponseEntity<CommonResponse>> resetPassword(
      Mono<ResetPasswordRequest> resetPasswordRequest);

  Mono<ResponseEntity<CommonResponse>> register(
      Flux<Part> email,
      Flux<Part> password,
      Flux<Part> username,
      Flux<Part> displayName,
      Flux<Part> city,
      Flux<Part> dateOfBirth,
      Flux<Part> gender,
      Flux<Part> avatar);
}
