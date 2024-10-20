package com.chat.auth_service.service;

import com.chat.auth_service.server.model.*;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.multipart.Part;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface AuthService {
  Mono<ResponseEntity<Login200Response>> login(Mono<LoginRequest> loginRequest, String requestId);

  Mono<ResponseEntity<RefreshToken200Response>> refreshToken(
      Mono<RefreshTokenRequest> refreshTokenRequest, String requestId);

  Mono<ResponseEntity<CommonResponse>> forgotPassword(
      Mono<ForgotPasswordRequest> forgotPasswordRequest, String requestId);

  Mono<ResponseEntity<CommonResponse>> resetPassword(
      Mono<ResetPasswordRequest> resetPasswordRequest, String requestId);

  Mono<ResponseEntity<CommonResponse>> changePassword(
      Mono<ChangePasswordRequest> changePasswordRequest, String requestId, UUID userId);

  Mono<ResponseEntity<CheckEmailExists200Response>> checkEmailExists(
      Mono<CheckEmailExistsRequest> checkEmailExistsRequest, String requestId);

  Mono<ResponseEntity<CheckUsernameExists200Response>> checkUsernameExists(
      Mono<CheckUsernameExistsRequest> checkUsernameExistsRequest, String requestId);

  Mono<ResponseEntity<CommonResponse>> register(
      Flux<Part> email,
      Flux<Part> password,
      Flux<Part> username,
      Flux<Part> displayName,
      Flux<Part> city,
      Flux<Part> dateOfBirth,
      Flux<Part> gender,
      Flux<Part> avatar,
      String requestId);
}
