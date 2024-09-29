package com.chat.auth_service.delegator;

import com.chat.auth_service.server.api.AuthApiDelegate;
import com.chat.auth_service.server.model.*;
import com.chat.auth_service.service.AuthService;
import com.chat.auth_service.service.MailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthApiDelegatorImpl implements AuthApiDelegate {
  private final AuthService authService;
  private final MailService mailService;
  private static final String USER_ID_HEADER = "userId";
  private static final String REQUEST_ID_HEADER = "requestId";

  // TODO: forgot password endpoint, reset password endpoint, change password endpoint

  @Override
  public Mono<ResponseEntity<CommonResponse>> forgotPassword(
      Mono<ForgotPasswordRequest> forgotPasswordRequest, ServerWebExchange exchange) {
    String requestId = extractRequestIdFromHeader(exchange);
    return authService.forgotPassword(forgotPasswordRequest, requestId);
  }

  @Override
  public Mono<ResponseEntity<Login200Response>> login(
      Mono<LoginRequest> loginRequest, ServerWebExchange exchange) {
    String requestId = extractRequestIdFromHeader(exchange);
    return authService.login(loginRequest,requestId);
  }

  @Override
  public Mono<ResponseEntity<CommonResponse>> loginOAuth(
      Mono<LoginOAuthRequest> oauthLoginRequest, ServerWebExchange exchange) {
    return AuthApiDelegate.super.loginOAuth(oauthLoginRequest, exchange);
  }

  @Override
  public Mono<ResponseEntity<CommonResponse>> register(
      Mono<RegisterRequest> registerRequest, ServerWebExchange exchange) {
    String requestId = extractRequestIdFromHeader(exchange);
    return authService.register(registerRequest, requestId);
  }

  @Override
  public Mono<ResponseEntity<CommonResponse>> resetPassword(
      Mono<ResetPasswordRequest> resetPasswordRequest, ServerWebExchange exchange) {
    String requestId = extractRequestIdFromHeader(exchange);
    return authService.resetPassword(resetPasswordRequest, requestId);
  }

  @Override
  public Mono<ResponseEntity<CommonResponse>> resendVerificationEmail(
      Mono<ResendVerificationEmailRequest> resendVerificationEmailRequest,
      ServerWebExchange exchange) {
    String requestId = extractRequestIdFromHeader(exchange);
    return mailService.rendSendVerificationEmail(resendVerificationEmailRequest, requestId);
  }

  @Override
  public Mono<ResponseEntity<VerifyEmail200Response>> verifyEmail(
      Mono<VerifyEmailRequest> verifyEmailRequest, ServerWebExchange exchange) {
    String requestId = extractRequestIdFromHeader(exchange);
    return mailService.verifyEmail(verifyEmailRequest, requestId);
  }

  @Override
  public Mono<ResponseEntity<RefreshToken200Response>> refreshToken(
      Mono<RefreshTokenRequest> refreshTokenRequest, ServerWebExchange exchange) {
    String requestId = extractRequestIdFromHeader(exchange);
    return authService.refreshToken(refreshTokenRequest, requestId);
  }

  @Override
  public Mono<ResponseEntity<CommonResponse>> changePassword(
      Mono<ChangePasswordRequest> changePasswordRequest, ServerWebExchange exchange) {
    String requestId = extractRequestIdFromHeader(exchange);
    UUID userId = extractUserIdFromHeader(exchange);
    return authService.changePassword(changePasswordRequest, requestId, userId);
  }

  private String extractRequestIdFromHeader(ServerWebExchange exchange) {
    String requestId = null;
    HttpHeaders headers = exchange.getRequest().getHeaders();

    log.info("Headers: {}", exchange.getRequest().getHeaders());
    if (headers.containsKey(REQUEST_ID_HEADER) && headers.get(REQUEST_ID_HEADER) != null) {
      requestId = headers.get(REQUEST_ID_HEADER).get(0);
    }

    if (requestId == null) {
      return UUID.randomUUID().toString();
    }
    log.info("hello: {}", requestId);
    return requestId;
  }

  private UUID extractUserIdFromHeader(ServerWebExchange exchange) {
    String userId = null;
    HttpHeaders headers = exchange.getRequest().getHeaders();
    if (headers.containsKey(USER_ID_HEADER) && headers.get(USER_ID_HEADER) != null) {
      userId = headers.get(USER_ID_HEADER).get(0);
    }

    if (userId == null) {
      throw new RuntimeException("User ID not found in header");
    }

    return UUID.fromString(userId);
  }
}
