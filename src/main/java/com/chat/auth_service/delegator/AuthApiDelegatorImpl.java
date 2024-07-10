package com.chat.auth_service.delegator;

import com.chat.auth_service.server.api.AuthApiDelegate;
import com.chat.auth_service.server.model.*;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthApiDelegatorImpl implements AuthApiDelegate {
    @Override
    public Mono<ResponseEntity<ForgotPassword200Response>> forgotPassword(ServerWebExchange exchange) {
        return AuthApiDelegate.super.forgotPassword(exchange);
    }

    @Override
    public Mono<ResponseEntity<Login200Response>> login(Mono<LoginRequest> loginRequest, ServerWebExchange exchange) {
        return AuthApiDelegate.super.login(loginRequest, exchange);
    }

    @Override
    public Mono<ResponseEntity<Login200Response>> loginOAuth(Mono<OAuthLoginRequest> oauthLoginRequest, ServerWebExchange exchange) {
        return AuthApiDelegate.super.loginOAuth(oauthLoginRequest, exchange);
    }

    @Override
    public Mono<ResponseEntity<Register200Response>> register(Mono<RegisterRequest> registerRequest, ServerWebExchange exchange) {
        return AuthApiDelegate.super.register(registerRequest, exchange);
    }

    @Override
    public Mono<ResponseEntity<ResetPassword200Response>> resetPassword(Mono<ResetPasswordRequest> resetPasswordRequest, ServerWebExchange exchange) {
        return AuthApiDelegate.super.resetPassword(resetPasswordRequest, exchange);
    }

    @Override
    public Mono<ResponseEntity<ResendEmailVerificationCodeForRegistration200Response>> resendEmailVerificationCodeForRegistration(ServerWebExchange exchange) {
        return AuthApiDelegate.super.resendEmailVerificationCodeForRegistration(exchange);
    }

    @Override
    public Mono<ResponseEntity<VerifyEmailForRegister200Response>> verifyEmailForRegister(Mono<VerifyEmailRequest> verifyEmailRequest, ServerWebExchange exchange) {
        return AuthApiDelegate.super.verifyEmailForRegister(verifyEmailRequest, exchange);
    }
}
