package com.chat.auth_service.service.implementation;

import com.chat.auth_service.entity.*;
import com.chat.auth_service.event.UserRegistrationEvent;
import com.chat.auth_service.exception.ApplicationException;
import com.chat.auth_service.exception.ErrorCode;
import com.chat.auth_service.repository.*;
import com.chat.auth_service.server.model.*;
import com.chat.auth_service.service.AuthService;
import com.chat.auth_service.service.KafkaProducer;
import com.chat.auth_service.utils.JwtUtils;
import com.chat.auth_service.utils.Utils;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
  private static final Logger log = LoggerFactory.getLogger(AuthServiceImpl.class);

  private final UserRepository userRepository;
  private final AuthenticationSettingRepository authenticationSettingRepository;
  private final LoginHistoryRepository loginHistoryRepository;
  private final PasswordEncoder passwordEncoder;
  private final ApplicationTokenRepository applicationTokenRepository;
  private final MailServiceImpl mailService;
  private final JwtUtils jwtUtils;
  private final KafkaProducer kafkaProducer;

  @Value("${jwt.limit-refresh-token-usage-consecutive-minutes}")
  private int LIMIT_REFRESH_TOKEN_USAGE_CONSECUTIVE_MINUTES;

  private final VerificationCodeRepository verificationCodeRepository;

  @Override
  public Mono<ResponseEntity<Login200Response>> login(Mono<LoginRequest> loginRequest) {
    return loginRequest.flatMap(
        request ->
            userRepository
                .findByEmail(request.getEmail())
                .switchIfEmpty(Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR1)))
                .flatMap(user -> validateAndSaveLoginHistoryRequest(request, user))
                .flatMap(
                    user -> {
                      // Generate and save refresh token
                      String accessToken = jwtUtils.generateAccessToken(user);
                      // TODO: save the login history
                      return saveRefreshToken(user)
                          .flatMap(
                              savedRefreshToken ->
                                  Mono.just(
                                      ResponseEntity.ok(
                                          mapLoginResponse(
                                              accessToken, savedRefreshToken.getToken()))));
                    }));
  }

  private Login200Response mapLoginResponse(String accessToken, String refreshToken) {
    return new Login200Response()
        .requestId(Utils.generateRequestId())
        .message("Login successful")
        .data(new Login200ResponseAllOfData().accessToken(accessToken).refreshToken(refreshToken));
  }

  @Override
  public Mono<ResponseEntity<RefreshToken200Response>> refreshToken(
      Mono<RefreshTokenRequest> refreshTokenRequest) {
    return refreshTokenRequest.flatMap(
        request ->
            applicationTokenRepository
                .findByToken(request.getRefreshToken())
                .switchIfEmpty(Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR16)))
                .flatMap(this::validateRefreshTokenAndGenerateNewAccessToken)
                .map(accessToken -> ResponseEntity.ok(mapRefreshTokenResponse(accessToken))));
  }

  private RefreshToken200Response mapRefreshTokenResponse(String accessToken) {
    return new RefreshToken200Response()
        .requestId(Utils.generateRequestId())
        .message("Refresh token successful")
        .data(new RefreshToken200ResponseAllOfData().accessToken(accessToken));
  }

  @Override
  public Mono<ResponseEntity<CommonResponse>> forgotPassword(
      Mono<ForgotPasswordRequest> forgotPasswordRequest) {
    return forgotPasswordRequest.flatMap(
        request -> {
          return userRepository
              .findByEmail(request.getEmail())
              .switchIfEmpty(Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR1)))
              .flatMap(
                  user -> {
                    VerificationCode verificationCode =
                        mailService.createEmailVerificationCodeForgotPassword(user);
                    return verificationCodeRepository
                        .save(verificationCode)
                        .doOnNext(
                            saveVerificationCode ->
                                mailService.sendVerificationEmail(
                                    "Email Verification for forgot password",
                                    user.getEmail(),
                                    verificationCode));
                  })
              .map(
                  verificationCode ->
                      Utils.createCommonSuccessResponse(
                          "Verification code is sent to your email. Please check your email to verify your account."));
        });
  }

  @Override
  public Mono<ResponseEntity<CommonResponse>> resetPassword(
      Mono<ResetPasswordRequest> resetPasswordRequest) {
    return resetPasswordRequest.flatMap(
        request -> {
          return applicationTokenRepository
              .findByToken(request.getResetPasswordToken())
              .switchIfEmpty(Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR19)))
              .flatMap(
                  token -> {
                    // validate the reset password token
                    ErrorCode errorCode = validResetPasswordToken(token);

                    if (errorCode != null) {
                      return Mono.error(new ApplicationException(errorCode));
                    }
                    String userId = jwtUtils.extractUserId(request.getResetPasswordToken());

                    // get the user and then reset the password
                    return userRepository
                        .findById(Utils.convertStringToUUID(userId))
                        .switchIfEmpty(Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR1)))
                        .flatMap(
                            user -> {
                              // resetting user password
                              user.setPasswordHash(
                                  passwordEncoder.encode(request.getNewPassword()));
                              // mark the token as used
                              token.setUsageCount(token.getUsageCount() + 1);

                              return userRepository
                                  .save(user)
                                  .then(applicationTokenRepository.save(token));
                            });
                  })
              .map(savedToken -> Utils.createCommonSuccessResponse("Reset password successfully"));
        });
  }

  private ErrorCode validResetPasswordToken(ApplicationToken token) {
    boolean isExpired = jwtUtils.isTokenExpired(token.getToken());
    boolean isUsed = token.getUsageCount() == token.getLimitUsageCount();

    if (isExpired || isUsed) {
      return ErrorCode.AUTH_ERROR20;
    }

    return null;
  }

  @Override
  public Mono<ResponseEntity<CommonResponse>> register(Mono<RegisterRequest> registerRequest) {
    // TODO: refactor code, move the util methods to Utils class
    return registerRequest.flatMap(
        request -> {
          // Check if email is already registered
          return createNewUserFromRequest(request)
              .flatMap(userRepository::save)
              .doOnNext(user -> this.sendUserRegistrationEventToDownStream(user, request))
              .flatMap(
                  savedUser -> {
                    AuthenticationSetting authenticationSetting =
                        createAuthenticationSetting(savedUser);
                    VerificationCode verificationCode =
                        mailService.createEmailVerificationCodeForAccountRegistration(savedUser);
                    return authenticationSettingRepository
                        .save(authenticationSetting)
                        .then(mailService.saveVerificationCode(verificationCode))
                        .doOnNext(
                            // TODO: move the title of the email to a constant
                            savedVerificationCode ->
                                mailService.sendVerificationEmail(
                                    "Verify email for account registration",
                                    savedUser.getEmail(),
                                    savedVerificationCode))
                        .then(Mono.just(savedUser));
                  })
              .map(
                  savedUser ->
                      Utils.createCommonSuccessResponse(
                          "Registration successful. Please check your email to verify your account."));
        });
  }

  private Mono<User> validateAndSaveLoginHistoryRequest(LoginRequest request, User user) {
    // Check if password is correct
    if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
      return saveFailedLoginHistory(user.getId(), request)
          .then(Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR5)));
    }

    // Check if account is verified
    if (user.getAccountStatus() == User.AccountStatus.UNVERIFIED) {
      return saveFailedLoginHistory(user.getId(), request)
          .then(Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR3)));
    }

    // TODO: save user login history here

    return Mono.just(user);
  }

  private Mono<LoginHistory> saveNewLoginHistoryWithMfa(
      LoginHistory loginHistory, AuthenticationSetting authenticationSetting) {
    return handleMfaLogin(loginHistory, authenticationSetting)
        .flatMap(
            mfaResult -> {
              loginHistory.setIsSuccessful(true);
              return loginHistoryRepository.save(loginHistory);
            });
  }

  // TODO: move this to util class
  private LoginHistory createNewLoginHistory(User user, LoginRequest request) {
    LoginHistory loginHistory = new LoginHistory();
    loginHistory.setUserId(user.getId());
    //    loginHistory.setIsSaved(false);
    loginHistory.setIsSuccessful(false);
    loginHistory.setIpAddress(request.getIpAddress());
    loginHistory.setUserAgent(request.getUserAgent());
    return loginHistory;
  }

  private Mono<ApplicationToken> saveRefreshToken(User user) {
    ApplicationToken refreshToken = new ApplicationToken();
    refreshToken.setToken(jwtUtils.generateRefreshToken(user));
    refreshToken.setTokenType(ApplicationToken.TokenType.REFRESH_TOKEN);
    refreshToken.setUsageCount(1); // TODO: move this to application.properties
    refreshToken.setLimitUsageCount(
        LIMIT_REFRESH_TOKEN_USAGE_CONSECUTIVE_MINUTES); // TODO: move this to application.properties
    refreshToken.setLastUsed(OffsetDateTime.now());

    return applicationTokenRepository.save(refreshToken);
  }

  private void sendUserRegistrationEventToDownStream(User user, RegisterRequest request) {
    UserRegistrationEvent.Gender gender =
        UserRegistrationEvent.Gender.valueOf(request.getGender().getValue());
    UserRegistrationEvent event =
        UserRegistrationEvent.builder()
            .userId(user.getId().toString())
            .email(user.getEmail())
            .city(request.getCity())
            .dateOfBirth(request.getDateOfBirth().toString())
            .displayName(request.getDisplayName())
            .gender(gender)
            .createdAt(user.getCreatedAt())
            .build();
    kafkaProducer.sendNewRegistryEvent(event);
  }

  // TODO: move this to util class
  private Mono<User> createNewUserFromRequest(RegisterRequest request) {
    return Mono.zip(
            userRepository.existsByEmail(request.getEmail()),
            userRepository.existsByUsername(request.getUsername()))
        .flatMap(
            tuple2 -> {
              Boolean existedByEmail = tuple2.getT1();
              Boolean existedByUsername = tuple2.getT2();

              if (existedByEmail) {
                return Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR2));
              }

              if (existedByUsername) {
                return Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR4));
              }
              User newUser = createNewUser(request);
              return Mono.just(newUser);
            });
  }

  // TODO: move this to util class
  private User createNewUser(RegisterRequest request) {
    User newUser = new User();
    newUser.setEmail(request.getEmail());
    newUser.setUsername(request.getUsername());
    newUser.setPasswordHash(passwordEncoder.encode(request.getPassword()));
    newUser.setAccountType(User.AccountType.NORMAL);
    newUser.setAccountStatus(
        User.AccountStatus.UNVERIFIED); // Set to INACTIVE until email is verified

    return newUser;
  }

  // TODO: move this to util class
  private AuthenticationSetting createAuthenticationSetting(User user) {
    AuthenticationSetting authSetting = new AuthenticationSetting();
    authSetting.setUserId(user.getId());
    authSetting.setMfaEnabled(false); // Default to false, can be enabled later
    return authSetting;
  }

  private Mono<String> validateRefreshTokenAndGenerateNewAccessToken(
      ApplicationToken refreshToken) {
    return Mono.just(refreshToken)
        .flatMap(
            token -> {
              // validate token
              ErrorCode errorCode = validateRefreshToken(token);
              if (errorCode != null) {
                return Mono.error(new ApplicationException(errorCode));
              }
              return Mono.just(refreshToken);
            })
        .flatMap(
            token -> {
              // extract user id and find user by id
              UUID userId =
                  Utils.convertStringToUUID(jwtUtils.extractUserId(refreshToken.getToken()));

              return userRepository
                  .findById(userId)
                  .switchIfEmpty(Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR1)));
            })
        .flatMap(
            user -> {
              // generate new access token
              String accessToken = jwtUtils.generateAccessToken(user);

              // update the refresh token
              refreshToken.setUsageCount(refreshToken.getUsageCount() + 1);
              refreshToken.setLastUsed(OffsetDateTime.now());

              return applicationTokenRepository.save(refreshToken).then(Mono.just(accessToken));
            });
  }

  private ErrorCode validateRefreshToken(ApplicationToken refreshToken) {
    if (!jwtUtils.validateRefreshToken(refreshToken.getToken())) {
      return ErrorCode.AUTH_ERROR15;
    }

    if (isUsageCountExceeded(refreshToken)) {
      return ErrorCode.AUTH_ERROR17;
    }

    if (isUsedTooRecently(refreshToken)) {
      return ErrorCode.AUTH_ERROR18;
    }

    return null;
  }

  private boolean isUsageCountExceeded(ApplicationToken refreshToken) {
    return refreshToken.getUsageCount() >= refreshToken.getLimitUsageCount();
  }

  private boolean isUsedTooRecently(ApplicationToken refreshToken) {
    Duration timeSinceLastUse = Duration.between(refreshToken.getLastUsed(), OffsetDateTime.now());
    return timeSinceLastUse.toMinutes() < LIMIT_REFRESH_TOKEN_USAGE_CONSECUTIVE_MINUTES;
  }

  private Mono<Void> saveFailedLoginHistory(UUID userId, LoginRequest loginRequest) {
    LoginHistory failedLogin = new LoginHistory();
    failedLogin.setUserId(userId);
    failedLogin.setIpAddress(loginRequest.getIpAddress());
    failedLogin.setUserAgent(loginRequest.getUserAgent());
    failedLogin.setIsSuccessful(false);
    return loginHistoryRepository.save(failedLogin).then();
  }

  private Mono<LoginHistory> handleMfaLogin(
      LoginHistory loginHistory, AuthenticationSetting authenticationSetting) {
    // TODO: Remove enableMFA field from AuthenticationSetting, use MFA method instead
    // TODO: Default MFA method is email verification code (It means that any login with new ip and
    // user agent will require email verification code or previous unsuccessful login)
    // Implement MFA logic here
    // This could involve generating and sending a verification code,
    // or checking a TOTP code, etc.
    // Return appropriate response or error
    //        return Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR6));
    return Mono.just(loginHistory);
  }
}
