package com.chat.auth_service.service.implementation;

import com.chat.auth_service.entity.*;
import com.chat.auth_service.exception.ApplicationException;
import com.chat.auth_service.exception.ErrorCode;
import com.chat.auth_service.repository.*;
import com.chat.auth_service.server.model.*;
import com.chat.auth_service.service.AuthService;
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
  private final ApplicationTokenRepository refreshTokenRepository;
  private final MailServiceImpl mailService;
  private final JwtUtils jwtUtils;

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
                .flatMap(
                    user ->
                        validateAndSaveLoginHistoryRequest(request, user)
                            .flatMap(
                                history -> {
                                  // Generate and save refresh token
                                  String accessToken = jwtUtils.generateAccessToken(user);
                                  return saveRefreshToken(user)
                                      .flatMap(
                                          refreshToken ->
                                              Mono.just(
                                                  ResponseEntity.ok(
                                                      new Login200Response()
                                                          .accessToken(accessToken))));
                                })));
  }

  @Override
  public Mono<ResponseEntity<RefreshTokenResponse>> refreshToken(
      Mono<RefreshTokenRequest> refreshTokenRequest) {
    return refreshTokenRequest.flatMap(
        request ->
            refreshTokenRepository
                .findByToken(request.getRefreshToken())
                .switchIfEmpty(Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR16)))
                .flatMap(this::validateRefreshTokenAndGenerateNewAccessToken)
                .map(
                    accessToken -> {
                      RefreshTokenResponse response = new RefreshTokenResponse();
                      response.setAccessToken(accessToken);
                      return ResponseEntity.ok(response);
                    }));
  }

  @Override
  public Mono<ResponseEntity<ForgotPassword200Response>> forgotPassword(
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
                  verificationCode -> {
                    ForgotPassword200Response response = new ForgotPassword200Response();
                    response.setMessage(
                        "Verification code is sent to your email. Please check your email to verify your account.");

                    return ResponseEntity.ok(response);
                  });
        });
  }

  @Override
  public Mono<ResponseEntity<Register200Response>> register(Mono<RegisterRequest> registerRequest) {
    // TODO: refactor code, move the util methods to Utils class
    return registerRequest.flatMap(
        request -> {
          // Check if email is already registered
          return createNewUserFromRequest(request)
              .flatMap(userRepository::save)
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
                  savedUser -> {
                    Register200Response response = new Register200Response();
                    response.setMessage(
                        "Registration successful. Please check your email to verify your account.");
                    return ResponseEntity.ok(response);
                  });
        });
  }

  private Mono<LoginHistory> validateAndSaveLoginHistoryRequest(LoginRequest request, User user) {
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

    return authenticationSettingRepository
        .findByUserId(user.getId())
        .zipWith(
            loginHistoryRepository
                .findByUserIdAndIpAddressAndUserAgent(
                    user.getId(), request.getIpAddress(), request.getUserAgent())
                .switchIfEmpty(Mono.just(createNewLoginHistory(user, request))))
        .flatMap(
            tuple2 -> {
              AuthenticationSetting authSettings = tuple2.getT1();
              LoginHistory loginHistory = tuple2.getT2();

              //              if (!loginHistory.getIsSaved()) {
              // Check if MFA is required
              if (authSettings.getMfaEnabled()) {
                return handleMfaLogin(user, request);
              }
              //              }

              if (!loginHistory.getIsSuccessful()) loginHistory.setIsSuccessful(true);

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
    refreshToken.setLimitUsageCount(5); // TODO: move this to application.properties
    refreshToken.setLastUsed(OffsetDateTime.now());

    return refreshTokenRepository.save(refreshToken);
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
                  Utils.convertStringToUUID(jwtUtils.extractUserID(refreshToken.getToken()));

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

              return refreshTokenRepository.save(refreshToken).then(Mono.just(accessToken));
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

  private Mono<LoginHistory> handleMfaLogin(User user, LoginRequest request) {
    // Implement MFA logic here
    // This could involve generating and sending a verification code,
    // or checking a TOTP code, etc.
    // Return appropriate response or error
    return Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR5));
  }
}
