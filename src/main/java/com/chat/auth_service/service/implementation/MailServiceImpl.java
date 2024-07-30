package com.chat.auth_service.service.implementation;

import static com.chat.auth_service.entity.VerificationCode.Type.*;

import com.chat.auth_service.entity.ApplicationToken;
import com.chat.auth_service.entity.LoginHistory;
import com.chat.auth_service.entity.User;
import com.chat.auth_service.entity.VerificationCode;
import com.chat.auth_service.exception.ApplicationException;
import com.chat.auth_service.exception.ErrorCode;
import com.chat.auth_service.repository.*;
import com.chat.auth_service.server.model.*;
import com.chat.auth_service.service.MailService;
import com.chat.auth_service.utils.JwtUtils;
import com.chat.auth_service.utils.MailUtils;
import com.chat.auth_service.utils.Utils;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
@Slf4j
public class MailServiceImpl implements MailService {
  private final ApplicationTokenRepository applicationTokenRepository;

  // TODO: refactor, move generation of verification code to another class
  private final UserRepository userRepository;
  private final VerificationCodeRepository verificationCodeRepository;
  private final MailUtils mailUtils;
  private final JwtUtils jwtUtils;

  private final String ACCESS_TOKEN_KEY = "accessToken";
  private final String REFRESH_TOKEN_KEY = "refreshToken";
  private final String RESET_PASSWORD_TOKEN_KEY = "resetPasswordToken";

  @Override
  public Mono<ResponseEntity<CommonResponse>> rendSendVerificationEmail(
      Mono<ResendVerificationEmailRequest> resendVerificationEmailRequest) {

    // TODO: some of the logic is the same as sending verification email;
    // TODO: clean tnis code
    return resendVerificationEmailRequest.flatMap(
        request -> {
          return userRepository
              .findByEmail(request.getEmail())
              // check if user exists
              .switchIfEmpty(Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR1)))
              // validate the request
              .flatMap(
                  user -> {
                    ErrorCode errorCode = validateEmailVerificationRequest(user, request.getType());
                    if (errorCode != null) {
                      return Mono.error(new ApplicationException(errorCode));
                    }

                    return Mono.just(user);
                  })
              // check the rate limit of resending the request
              .flatMap(
                  user -> {
                    return verificationCodeRepository
                        .findByUserEmailAndTypeLatest(
                            user.getEmail(), VerificationCode.Type.valueOf(request.getType()))
                        .flatMap(
                            verificationCode -> {
                              boolean exceededRateLimit = checkExceedRateLimit(verificationCode);
                              if (exceededRateLimit) {
                                return Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR10));
                              }

                              return Mono.just(user);
                            })
                        // if not verification exist, then continue processing
                        .switchIfEmpty(Mono.just(user));
                  })
              // create new verification code and save it
              .flatMap(
                  user -> {
                    VerificationCode verificationCode = new VerificationCode();
                    verificationCode.setType(VerificationCode.Type.valueOf(request.getType()));
                    verificationCode.setExpiration(
                        OffsetDateTime.now()
                            .plusMinutes(30)); // TODO: this should be in application.properties
                    verificationCode.setUserEmail(user.getEmail());
                    verificationCode.setCode(generateMailVerificationCode());

                    return verificationCodeRepository.save(verificationCode);
                  })
              .map(
                  verificationCode -> {

                    // email is sent asynchronously
                    log.info("i am sending the verification email");
                    mailUtils.sendVerificationEmail(
                        "EMAIL VERIFICATION", request.getEmail(), verificationCode);

                    CommonResponse response = new CommonResponse();
                    response.setMessage("Email is being sent successfully");
                    return ResponseEntity.ok(response);
                  });
        });
  }

  private LoginHistory createNewLoginHistory(User user, LoginRequest request) {
    LoginHistory loginHistory = new LoginHistory();
    loginHistory.setUserId(user.getId());
    //    loginHistory.setIsSaved(false);
    loginHistory.setIsSuccessful(false);
    loginHistory.setIpAddress(request.getIpAddress());
    loginHistory.setUserAgent(request.getUserAgent());
    return loginHistory;
  }

  @Override
  public Mono<ResponseEntity<VerifyEmail200Response>> verifyEmail(
      Mono<VerifyEmailRequest> verifyEmailRequest) {
    return verifyEmailRequest.flatMap(
        request -> {
          return getUserByEmailAndThrowExceptionNotExists(request.getEmail())
              .flatMap(
                  user -> {
                    ErrorCode errorCode = validateEmailVerificationRequest(user, request.getType());

                    if (errorCode != null) {
                      return Mono.error(new ApplicationException(errorCode));
                    }

                    VerificationCode.Type requestType =
                        VerificationCode.Type.valueOf(request.getType());

                    if (requestType.equals(ACCOUNT_REGISTRATION)) {
                      return handleVerifyEmailForRegistration(request, user);
                    } else if (requestType.equals(FORGOT_PASSWORD)) {
                      return handleVerifyEmailForForgotPassword(request, user);
                    } else {
                      return Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR11));
                    }
                  })
              .map(data -> ResponseEntity.ok(mapToVerifyEmail200Response(data)));
        });
  }

  private VerifyEmail200Response mapToVerifyEmail200Response(VerifyEmail200ResponseAllOfData data) {
    return new VerifyEmail200Response()
        .requestId(Utils.generateRequestId())
        .message("Email verified successfully!")
        .data(data);
  }

  @Override
  public void sendVerificationEmail(String title, String email, VerificationCode verificationCode) {
    mailUtils.sendVerificationEmail(title, email, verificationCode);
  }

  public String generateMailVerificationCode() {
    // Implement a method to generate a random verification code
    return UUID.randomUUID().toString().substring(0, 6).toUpperCase();
  }

  public Mono<VerificationCode> saveVerificationCode(VerificationCode verificationCode) {
    return verificationCodeRepository.save(verificationCode);
  }

  public VerificationCode createEmailVerificationCodeForAccountRegistration(User user) {
    VerificationCode verificationCode =
        createEmailVerificationCode(user.getEmail(), ACCOUNT_REGISTRATION);
    verificationCode.setExpiration(OffsetDateTime.now().plusDays(30)); // 30 days validity

    return verificationCode;
  }

  public VerificationCode createEmailVerificationCodeForgotPassword(User user) {
    VerificationCode verificationCode =
        createEmailVerificationCode(user.getEmail(), FORGOT_PASSWORD);
    verificationCode.setExpiration(OffsetDateTime.now().plusMinutes(30)); // 30 minutes validity

    return verificationCode;
  }

  public VerificationCode createEmailVerificationCode(String email, VerificationCode.Type type) {
    VerificationCode verificationCode = new VerificationCode();
    verificationCode.setUserEmail(email);
    verificationCode.setType(type);
    verificationCode.setCode(generateVerificationCode());

    return verificationCode;
  }

  // TODO: move this to util class
  private String generateVerificationCode() {
    // Implement a method to generate a random verification code
    return UUID.randomUUID().toString().substring(0, 6).toUpperCase();
  }

  private Mono<VerifyEmail200ResponseAllOfData> handleVerifyEmailForRegistration(
      VerifyEmailRequest request, User user) {
    return verificationCodeRepository
        .findByUserEmailAndCodeAndTypeLatest(
            request.getEmail(), request.getVerificationCode(), ACCOUNT_REGISTRATION)
        .switchIfEmpty(Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR12)))
        .flatMap(
            verificationCode -> {
              ErrorCode errorCode =
                  validateVerificationCode(verificationCode, request.getVerificationCode());

              if (errorCode != null) {
                return Mono.error(new ApplicationException(errorCode));
              }

              // check if user's account was already verified
              if (!Objects.equals(User.AccountStatus.UNVERIFIED, user.getAccountStatus())) {
                return Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR9));
              }

              // if everything is valid, verify the user account
              user.setAccountStatus(User.AccountStatus.ACTIVE);
              user.setUpdatedAt(OffsetDateTime.now());

              return userRepository.save(user);
            })
        .map(saveUser -> mapToVerifyEmail200Response(ACCOUNT_REGISTRATION.toString(), Map.of()));
  }

  private Mono<VerifyEmail200ResponseAllOfData> handleVerifyEmailForForgotPassword(
      VerifyEmailRequest request, User user) {
    return verificationCodeRepository
        .findByUserEmailAndCodeAndTypeLatest(
            request.getEmail(), request.getVerificationCode(), FORGOT_PASSWORD)
        .switchIfEmpty(Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR12)))
        .flatMap(
            verificationCode -> {
              ErrorCode errorCode =
                  validateVerificationCode(verificationCode, request.getVerificationCode());
              if (errorCode != null) {
                return Mono.error(new ApplicationException(errorCode));
              }

              ApplicationToken resetPasswordToken =
                  createResetPasswordToken(jwtUtils.generateResetPasswordToken(user));

              return applicationTokenRepository.save(resetPasswordToken);
            })
        .map(
            resetPasswordToken -> {
              Map<String, String> tokenMap =
                  Map.of(RESET_PASSWORD_TOKEN_KEY, resetPasswordToken.getToken());
              String type = FORGOT_PASSWORD.toString();

              return mapToVerifyEmail200Response(type, tokenMap);
            });
  }

  private VerifyEmail200ResponseAllOfData mapToVerifyEmail200Response(
      String type, Map<String, String> tokens) {
    return new VerifyEmail200ResponseAllOfData().type(type).tokens(tokens);
  }

  private ApplicationToken createResetPasswordToken(String token) {
    ApplicationToken resetPasswordToken = new ApplicationToken();
    resetPasswordToken.setToken(token);
    resetPasswordToken.setTokenType(ApplicationToken.TokenType.RESET_PASSWORD_TOKEN);
    resetPasswordToken.setUsageCount(0); // TODO: move this to application.properties
    resetPasswordToken.setLimitUsageCount(1); // TODO: move this to application.properties
    resetPasswordToken.setLastUsed(OffsetDateTime.now());

    return resetPasswordToken;
  }

  private ErrorCode validateVerificationCode(
      VerificationCode verificationCodeInDB, String codeSentByUSer) {
    // check if verification code is correct
    boolean correctCode = verificationCodeInDB.getCode().equals(codeSentByUSer);
    if (!correctCode) {
      return ErrorCode.AUTH_ERROR12;
    }

    // check if verification code expired
    boolean codeExpired = OffsetDateTime.now().isAfter(verificationCodeInDB.getExpiration());
    if (codeExpired) {
      return ErrorCode.AUTH_ERROR13;
    }

    return null;
  }

  private Mono<User> getUserByEmailAndThrowExceptionNotExists(String email) {
    return userRepository
        .findByEmail(email)
        .switchIfEmpty(Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR1)));
  }

  private boolean checkExceedRateLimit(VerificationCode verificationCode) {
    //    verificationCode.get
    OffsetDateTime now = OffsetDateTime.now();
    Duration between = Duration.between(verificationCode.getCreatedAt(), now);
    log.info("now: {}", now);
    log.info("createdAt: {}", verificationCode.getCreatedAt());

    // TODO: use Bucket4j library for rate limit instead of checking the database
    return !now.isAfter(verificationCode.getCreatedAt())
        || between.toSeconds() < 120; // TODO: this 120 value should be in application.properties
  }

  private ErrorCode validateEmailVerificationRequest(User user, String emailVerificationType) {
    // check if the request type for sending email is valid
    boolean isValidRequestType =
        Objects.nonNull(emailVerificationType)
            && Arrays.stream(values())
                .anyMatch(type -> type.name().equals(emailVerificationType.toUpperCase()));
    if (!isValidRequestType) {
      return ErrorCode.AUTH_ERROR8;
    }

    VerificationCode.Type requestType = VerificationCode.Type.valueOf(emailVerificationType);
    // if user is already verified, then will not process the ACCOUNT_REGISTRATION verification
    // request
    if (requestType.equals(ACCOUNT_REGISTRATION)
        && !Objects.equals(User.AccountStatus.UNVERIFIED, user.getAccountStatus())) {
      return ErrorCode.AUTH_ERROR9;
    }

    return null;
  }
}
