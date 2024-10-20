package com.chat.auth_service.service.implementation;

import com.chat.auth_service.entity.*;
import com.chat.auth_service.event.UserRegistrationEvent;
import com.chat.auth_service.exception.ApplicationException;
import com.chat.auth_service.exception.ErrorCode;
import com.chat.auth_service.repository.*;
import com.chat.auth_service.server.model.*;
import com.chat.auth_service.service.AuthService;
import com.chat.auth_service.service.KafkaProducer;
import com.chat.auth_service.service.MediaService;
import com.chat.auth_service.utils.JwtUtils;
import com.chat.auth_service.utils.Utils;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.multipart.FilePart;
import org.springframework.http.codec.multipart.Part;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
  private final UserRepository userRepository;
  private final AuthenticationSettingRepository authenticationSettingRepository;
  private final LoginHistoryRepository loginHistoryRepository;
  private final PasswordEncoder passwordEncoder;
  private final ApplicationTokenRepository applicationTokenRepository;
  private final MailServiceImpl mailService;
  private final JwtUtils jwtUtils;
  private final KafkaProducer kafkaProducer;
  private final MediaService mediaService;
  private final ObjectMapper objectMapper;
  private final VerificationCodeRepository verificationCodeRepository;

  @Value("${jwt.limit-refresh-token-usage-consecutive-minutes}")
  private int LIMIT_REFRESH_TOKEN_USAGE_CONSECUTIVE_MINUTES;

  @Override
  public Mono<ResponseEntity<Login200Response>> login(
      Mono<LoginRequest> loginRequest, String requestId) {
    return loginRequest.flatMap(
        request ->
            userRepository
                .findByEmail(request.getEmail())
                .switchIfEmpty(
                    Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR1, requestId)))
                .flatMap(user -> validateAndSaveLoginHistoryRequest(request, user, requestId))
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
      Mono<RefreshTokenRequest> refreshTokenRequest, String requestId) {
    return refreshTokenRequest.flatMap(
        request ->
            applicationTokenRepository
                .findByToken(request.getRefreshToken())
                .switchIfEmpty(Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR16)))
                .flatMap(token -> validateRefreshTokenAndGenerateNewAccessToken(token, requestId))
                .map(
                    accessToken ->
                        ResponseEntity.ok(mapRefreshTokenResponse(accessToken, requestId))));
  }

  private RefreshToken200Response mapRefreshTokenResponse(String accessToken, String requestId) {
    return new RefreshToken200Response()
        .requestId(requestId)
        .message("Refresh token successful")
        .data(new RefreshToken200ResponseAllOfData().accessToken(accessToken));
  }

  @Override
  public Mono<ResponseEntity<CommonResponse>> forgotPassword(
      Mono<ForgotPasswordRequest> forgotPasswordRequest, String requestId) {
    return forgotPasswordRequest.flatMap(
        request -> {
          return userRepository
              .findByEmail(request.getEmail())
              .switchIfEmpty(Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR1, requestId)))
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
                          "Verification code is sent to your email. Please check your email to verify your account.",
                          requestId));
        });
  }

  @Override
  public Mono<ResponseEntity<CommonResponse>> resetPassword(
      Mono<ResetPasswordRequest> resetPasswordRequest, String requestId) {
    return resetPasswordRequest.flatMap(
        request -> {
          return applicationTokenRepository
              .findByToken(request.getResetPasswordToken())
              .switchIfEmpty(
                  Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR19, requestId)))
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
                        .switchIfEmpty(
                            Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR1, requestId)))
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
              .map(
                  savedToken ->
                      Utils.createCommonSuccessResponse("Reset password successfully", requestId));
        });
  }

  @Override
  public Mono<ResponseEntity<CommonResponse>> changePassword(
      Mono<ChangePasswordRequest> changePasswordRequest, String requestId, UUID userId) {
    return changePasswordRequest.flatMap(
        request -> {
          return userRepository
              .findById(userId)
              .flatMap(
                  user -> {
                    String oldPassword = request.getOldPassword();
                    String newPassword = request.getNewPassword();
                    if (passwordEncoder.matches(oldPassword, user.getPasswordHash())) {
                      user.setPasswordHash(passwordEncoder.encode(newPassword));
                      return userRepository
                          .save(user)
                          .then(
                              Mono.just(
                                  Utils.createCommonSuccessResponse(
                                      "Change password successfully", requestId)));
                    } else {
                      throw new ApplicationException(ErrorCode.AUTH_ERROR21, requestId);
                    }
                  });
        });
  }

  @Override
  public Mono<ResponseEntity<CheckEmailExists200Response>> checkEmailExists(
      Mono<CheckEmailExistsRequest> checkEmailExistsRequest, String requestId) {
    return checkEmailExistsRequest.flatMap(
        request ->
            userRepository
                .existsByEmail(request.getEmail())
                .flatMap(
                    isExist ->
                        Boolean.TRUE.equals(isExist)
                            ? Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR2))
                            : Mono.just(
                                ResponseEntity.ok(Utils.mapCheckEmailExistsResponse(requestId))))
                .doOnError(e -> log.error("Error checking email exists", e)));
  }

  @Override
  public Mono<ResponseEntity<CheckUsernameExists200Response>> checkUsernameExists(
      Mono<CheckUsernameExistsRequest> checkUsernameExistsRequest, String requestId) {
    return checkUsernameExistsRequest.flatMap(
        request ->
            userRepository
                .existsByUsername(request.getUsername())
                .flatMap(
                    isExist ->
                        Boolean.TRUE.equals(isExist)
                            ? Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR2))
                            : Mono.just(
                                ResponseEntity.ok(Utils.mapCheckUsernameExistsResponse(requestId))))
                .doOnError(e -> log.error("Error checking email exists", e)));
  }

  private ErrorCode validResetPasswordToken(ApplicationToken token) {
    boolean isExpired = jwtUtils.isTokenExpired(token.getToken());
    boolean isUsed = token.getUsageCount() == token.getLimitUsageCount();

    if (isExpired || isUsed) {
      return ErrorCode.AUTH_ERROR20;
    }

    return null;
  }

  public Mono<ResponseEntity<CommonResponse>> register(
      Flux<Part> email,
      Flux<Part> password,
      Flux<Part> username,
      Flux<Part> displayName,
      Flux<Part> city,
      Flux<Part> dateOfBirth,
      Flux<Part> gender,
      Flux<Part> avatar,
      String requestId) {
    return Mono.zip(
            Utils.extractValue(email),
            Utils.extractValue(password),
            Utils.extractValue(username),
            Utils.extractValue(displayName),
            Utils.extractValue(city),
            Utils.extractDateValue(dateOfBirth),
            Utils.extractValue(gender),
            Utils.extractFile(avatar))
        .publishOn(Schedulers.boundedElastic())
        .flatMap(
            tuple -> {
              String emailStr = tuple.getT1();
              String passwordStr = tuple.getT2();
              String usernameStr = tuple.getT3();
              String displayNameStr = tuple.getT4();
              String cityStr = tuple.getT5();
              LocalDate dateOfBirthStr = tuple.getT6();
              String genderStr = tuple.getT7();
              FilePart avatarFile = tuple.getT8();

              Mono<String> uploadMono =
                  avatarFile != null
                      ? mediaService
                          .uploadImage(
                              "register", UUID.randomUUID().toString(), Mono.just(avatarFile))
                          .mapNotNull(
                              response -> {
                                MediaResource mediaResource =
                                    objectMapper.convertValue(response, MediaResource.class);
                                return mediaResource.getSecureUrl();
                              })
                      : Mono.empty();

              return uploadMono
                  .flatMap(
                      secureUrl ->
                          createNewUserFromParts(emailStr, passwordStr, usernameStr)
                              .flatMap(
                                  user ->
                                      userRepository
                                          .save(user)
                                          .doOnNext(
                                              savedUser ->
                                                  sendUserRegistrationEventToDownStream(
                                                      savedUser,
                                                      usernameStr,
                                                      emailStr,
                                                      cityStr,
                                                      dateOfBirthStr,
                                                      displayNameStr,
                                                      genderStr,
                                                      secureUrl // Pass secureUrl here
                                                      ))))
                  .flatMap(this::handleUserRegistration)
                  .map(
                      savedUser ->
                          Utils.createCommonSuccessResponse(
                              "Registration successful. Please check your email to verify your account.",
                              requestId));
            });
  }

  private Mono<User> handleUserRegistration(User savedUser) {
    AuthenticationSetting authenticationSetting = createAuthenticationSetting(savedUser);
    VerificationCode verificationCode =
        mailService.createEmailVerificationCodeForAccountRegistration(savedUser);

    return authenticationSettingRepository
        .save(authenticationSetting)
        .then(mailService.saveVerificationCode(verificationCode))
        .doOnNext(
            savedVerificationCode ->
                mailService.sendVerificationEmail(
                    "Email Verification for account registration",
                    savedUser.getEmail(),
                    savedVerificationCode))
        .thenReturn(savedUser);
  }

  private Mono<User> validateAndSaveLoginHistoryRequest(
      LoginRequest request, User user, String requestId) {
    // Check if password is correct
    if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
      return saveFailedLoginHistory(user.getId(), request)
          .then(Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR5, requestId)));
    }

    // Check if account is verified
    if (user.getAccountStatus() == User.AccountStatus.UNVERIFIED) {
      return saveFailedLoginHistory(user.getId(), request)
          .then(Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR3, requestId)));
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

  private void sendUserRegistrationEventToDownStream(
      User user,
      String usernameStr,
      String emailStr,
      String cityStr,
      LocalDate dateOfBirthStr,
      String displayNameStr,
      String genderStr,
      String avatar) {

    UserRegistrationEvent.Gender gender =
        UserRegistrationEvent.Gender.valueOf(genderStr.toLowerCase());

    UserRegistrationEvent event =
        UserRegistrationEvent.builder()
            .userId(user.getId().toString())
            .username(usernameStr)
            .email(emailStr)
            .city(cityStr)
            .dateOfBirth(dateOfBirthStr.toString())
            .displayName(displayNameStr)
            .gender(gender)
            .createdAt(user.getCreatedAt())
            .avatar(avatar)
            .build();
    kafkaProducer.sendNewRegistryEvent(event);
  }

  // TODO: move this to util class
  private Mono<User> createNewUserFromParts(String email, String password, String username) {
    // Check if email and username are unique
    return Mono.zip(userRepository.existsByEmail(email), userRepository.existsByUsername(username))
        .flatMap(
            tuple2 -> {
              Boolean existedByEmail = tuple2.getT1();
              Boolean existedByUsername = tuple2.getT2();

              if (Boolean.TRUE.equals(existedByEmail)) {
                return Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR2));
              }

              if (Boolean.TRUE.equals(existedByUsername)) {
                return Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR4));
              }

              return Mono.just(
                  User.builder()
                      .email(email)
                      .username(username)
                      .passwordHash(passwordEncoder.encode(password))
                      .accountType(User.AccountType.NORMAL)
                      .accountStatus(User.AccountStatus.UNVERIFIED)
                      .build());
            })
        .onErrorMap(
            e ->
                e instanceof ApplicationException
                    ? e
                    : new RuntimeException("Error creating user: " + e.getMessage()));
  }

  // TODO: move this to util class
  private AuthenticationSetting createAuthenticationSetting(User user) {
    AuthenticationSetting authSetting = new AuthenticationSetting();
    authSetting.setUserId(user.getId());
    authSetting.setMfaEnabled(false); // Default to false, can be enabled later
    return authSetting;
  }

  private Mono<String> validateRefreshTokenAndGenerateNewAccessToken(
      ApplicationToken refreshToken, String requestId) {
    return Mono.just(refreshToken)
        .flatMap(
            token -> {
              // validate token
              ErrorCode errorCode = validateRefreshToken(token);
              if (errorCode != null) {
                return Mono.error(new ApplicationException(errorCode, requestId));
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
                  .switchIfEmpty(
                      Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR1, requestId)));
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
