package com.chat.auth_service.delegator;

import com.chat.auth_service.server.api.AuthApiDelegate;
import com.chat.auth_service.server.model.*;
import com.chat.auth_service.service.AuthService;
import com.chat.auth_service.service.MailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.multipart.Part;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthApiDelegatorImpl implements AuthApiDelegate {
  private final AuthService authService;
  private final MailService mailService;

  // TODO: forgot password endpoint, reset password endpoint, change password endpoint

  @Override
  public Mono<ResponseEntity<CommonResponse>> forgotPassword(
      Mono<ForgotPasswordRequest> forgotPasswordRequest, ServerWebExchange exchange) {
    return authService.forgotPassword(forgotPasswordRequest);
  }

  @Override
  public Mono<ResponseEntity<Login200Response>> login(
      Mono<LoginRequest> loginRequest, ServerWebExchange exchange) {
    return authService.login(loginRequest);
  }

  @Override
  public Mono<ResponseEntity<CommonResponse>> loginOAuth(
      Mono<LoginOAuthRequest> oauthLoginRequest, ServerWebExchange exchange) {
    return AuthApiDelegate.super.loginOAuth(oauthLoginRequest, exchange);
  }

  @Override
  public Mono<ResponseEntity<CommonResponse>> register(
      Flux<Part> email,
      Flux<Part> password,
      Flux<Part> username,
      Flux<Part> displayName,
      Flux<Part> city,
      Flux<Part> dateOfBirth,
      Flux<Part> gender,
      Flux<Part> avatar,
      ServerWebExchange exchange) {
    return authService.register(
        email, password, username, displayName, city, dateOfBirth, gender, avatar);
  }

  @Override
  public Mono<ResponseEntity<CommonResponse>> resetPassword(
      Mono<ResetPasswordRequest> resetPasswordRequest, ServerWebExchange exchange) {
    return authService.resetPassword(resetPasswordRequest);
  }

  @Override
  public Mono<ResponseEntity<CommonResponse>> resendVerificationEmail(
      Mono<ResendVerificationEmailRequest> resendVerificationEmailRequest,
      ServerWebExchange exchange) {
    return mailService.rendSendVerificationEmail(resendVerificationEmailRequest);
  }

  @Override
  public Mono<ResponseEntity<VerifyEmail200Response>> verifyEmail(
      Mono<VerifyEmailRequest> verifyEmailRequest, ServerWebExchange exchange) {
    return mailService.verifyEmail(verifyEmailRequest);
  }

  @Override
  public Mono<ResponseEntity<RefreshToken200Response>> refreshToken(
      Mono<RefreshTokenRequest> refreshTokenRequest, ServerWebExchange exchange) {
    return authService.refreshToken(refreshTokenRequest);
  }
}
