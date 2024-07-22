package com.chat.auth_service.service;

import com.chat.auth_service.entity.VerificationCode;
import com.chat.auth_service.server.model.CommonResponse;
import com.chat.auth_service.server.model.ResendVerificationEmailRequest;
import com.chat.auth_service.server.model.VerifyEmailRequest;
import com.chat.auth_service.server.model.VerifyEmailResponse;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;

public interface MailService {

  Mono<ResponseEntity<CommonResponse>> rendSendVerificationEmail(
      Mono<ResendVerificationEmailRequest> resendVerificationEmailRequest);

  Mono<ResponseEntity<VerifyEmailResponse>> verifyEmail(
      Mono<VerifyEmailRequest> verifyEmailRequest);

  void sendVerificationEmail(
      String verifyEmail, String email, VerificationCode savedVerificationCode);
}
