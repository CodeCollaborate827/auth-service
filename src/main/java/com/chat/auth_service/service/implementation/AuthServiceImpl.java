package com.chat.auth_service.service.implementation;

import static com.chat.auth_service.entity.VerificationCode.Type.*;

import com.chat.auth_service.entity.*;
import com.chat.auth_service.exception.ApplicationException;
import com.chat.auth_service.exception.ErrorCode;
import com.chat.auth_service.repository.*;
import com.chat.auth_service.server.model.*;
import com.chat.auth_service.service.AuthService;
import com.chat.auth_service.utils.JwtUtils;
import com.chat.auth_service.utils.MailUtils;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
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
  private final RefreshTokenRepository refreshTokenRepository;
  private final VerificationCodeRepository verificationCodeRepository;
  private final MailUtils mailUtils;
  private final JwtUtils jwtUtils;

  @Value("${jwt.limit-refresh-token-usage-consecutive-minutes}")
  private int LIMIT_REFRESH_TOKEN_USAGE_CONSECUTIVE_MINUTES;

  private final String ACCESS_TOKEN_KEY = "accessToken";
  private final String REFRESH_TOKEN_KEY = "refreshToken";
  private final String RESET_PASSWORD_TOKEN_KEY = "resetPasswordToken";

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
                                  String accessToken = jwtUtils.generateAccessToken(user, history);
                                  return saveRefreshToken(user, history)
                                      .flatMap(
                                          refreshToken ->
                                              Mono.just(
                                                  ResponseEntity.ok(
                                                      new Login200Response()
                                                          .accessToken(accessToken))));
                                })));
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

  private LoginHistory createNewLoginHistory(User user, LoginRequest request) {
    LoginHistory loginHistory = new LoginHistory();
    loginHistory.setUserId(user.getId());
    //    loginHistory.setIsSaved(false);
    loginHistory.setIsSuccessful(false);
    loginHistory.setIpAddress(request.getIpAddress());
    loginHistory.setUserAgent(request.getUserAgent());
    return loginHistory;
  }

  private Mono<RefreshToken> saveRefreshToken(User user, LoginHistory loginHistory) {
    RefreshToken refreshToken = new RefreshToken();
    refreshToken.setLoginHistoryId(loginHistory.getId());
    refreshToken.setRefreshToken(jwtUtils.generateRefreshToken(user, loginHistory));
    refreshToken.setUsageCount(1);
    refreshToken.setLimitUsageCount(5);
    refreshToken.setLastUsed(OffsetDateTime.now());

    return refreshTokenRepository.save(refreshToken);
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
                    VerificationCode verificationCode = createVerificationCode(savedUser);
                    return authenticationSettingRepository
                        .save(authenticationSetting)
                        .then(verificationCodeRepository.save(verificationCode))
                        .doOnNext(
                            savedVerificationCode ->
                                mailUtils.sendVerificationEmail(
                                    "Verify email", savedUser.getEmail(), savedVerificationCode))
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

  private VerificationCode createVerificationCode(User user) {
    VerificationCode verificationCode = new VerificationCode();
    verificationCode.setUserId(user.getId());
    verificationCode.setType(ACCOUNT_REGISTRATION);
    verificationCode.setCode(generateVerificationCode()); // Implement this method
    verificationCode.setExpiration(OffsetDateTime.now().plusHours(24)); // 24 hours validity

    return verificationCode;
  }

  private AuthenticationSetting createAuthenticationSetting(User user) {
    AuthenticationSetting authSetting = new AuthenticationSetting();
    authSetting.setUserId(user.getId());
    authSetting.setMfaEnabled(false); // Default to false, can be enabled later
    return authSetting;
  }

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
                    ErrorCode errorCode = validateResendEmailRequest(user, request.getType());
                    if (errorCode != null) {
                      return Mono.error(new ApplicationException(errorCode));
                    }

                    return Mono.just(user);
                  })
              // check the rate limit of resending the request
              .flatMap(
                  user -> {
                    return verificationCodeRepository
                        .findByUserIdAndTypeLatest(
                            user.getId(), VerificationCode.Type.valueOf(request.getType()))
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
                    verificationCode.setUserId(user.getId());
                    verificationCode.setCode(generateVerificationCode());

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

  @Override
  public Mono<ResponseEntity<VerifyEmailResponse>> verifyEmail(
      Mono<VerifyEmailRequest> verifyEmailRequest) {
    return verifyEmailRequest.flatMap(
        request -> {
          return getUserByEmailAndThrowExceptionNotExists(request.getEmail())
              .flatMap(
                  user -> {
                    ErrorCode errorCode = validateResendEmailRequest(user, request.getType());

                    if (errorCode != null) {
                      return Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR10));
                    }

                    VerificationCode.Type requestType = valueOf(request.getType());

                    if (request.equals(ACCOUNT_REGISTRATION)) {
                      return handleVerifyEmailForRegistration(request, user);
                    } else if (request.equals(FORGOT_PASSWORD)) {
                      return handleVerifyEmailForForgotPassword(request, user);
                    } else {
                      return Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR11));
                    }
                  })
              .map(ResponseEntity.ok()::body);
        });
  }

  @Override
  public Mono<ResponseEntity<RefreshTokenResponse>> refreshToken(
      Mono<RefreshTokenRequest> refreshTokenRequest) {
    return refreshTokenRequest.flatMap(
        request ->
            refreshTokenRepository
                .findByRefreshToken(request.getRefreshToken())
                .switchIfEmpty(Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR16)))
                .zipWhen(this::checkIfRefreshTokenAvailableToGenerate)
                .flatMap(
                    tuple2 ->
                        generateAccessTokenAndSaveRefreshToken(tuple2.getT1(), tuple2.getT2())
                            .map(
                                accessToken -> {
                                  RefreshTokenResponse response = new RefreshTokenResponse();
                                  response.setAccessToken(accessToken);
                                  return ResponseEntity.ok(response);
                                })));
  }

  private Mono<String> generateAccessTokenAndSaveRefreshToken(
      RefreshToken refreshToken, LoginHistory loginHistory) {
    return userRepository
        .findById(loginHistory.getUserId())
        .flatMap(
            user -> {
              // generate new access token
              String accessToken = jwtUtils.generateAccessToken(user, loginHistory);

              // update the refresh token
              refreshToken.setUsageCount(refreshToken.getUsageCount() + 1);
              refreshToken.setLastUsed(OffsetDateTime.now());

              return refreshTokenRepository
                  .save(refreshToken)
                  .map(
                      savedRefreshToken -> {
                        return accessToken;
                      });
            });
  }

  private Mono<LoginHistory> checkIfRefreshTokenAvailableToGenerate(RefreshToken refreshToken) {
    return loginHistoryRepository
        .findById(refreshToken.getLoginHistoryId())
        .flatMap(loginHistory -> validateRefreshToken(refreshToken, loginHistory))
        .switchIfEmpty(Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR16)));
  }

  private Mono<LoginHistory> validateRefreshToken(
      RefreshToken refreshToken, LoginHistory loginHistory) {
    if (!jwtUtils.validateRefreshToken(refreshToken.getRefreshToken(), loginHistory)) {
      return Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR15));
    }

    if (isUsageCountExceeded(refreshToken)) {
      return Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR17));
    }

    if (isUsedTooRecently(refreshToken)) {
      return Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR18));
    }

    return Mono.just(loginHistory);
  }

  private boolean isUsageCountExceeded(RefreshToken refreshToken) {
    return refreshToken.getUsageCount() >= refreshToken.getLimitUsageCount();
  }

  private boolean isUsedTooRecently(RefreshToken refreshToken) {
    Duration timeSinceLastUse = Duration.between(refreshToken.getLastUsed(), OffsetDateTime.now());
    return timeSinceLastUse.toMinutes() < LIMIT_REFRESH_TOKEN_USAGE_CONSECUTIVE_MINUTES;
  }

  private Mono<VerifyEmailResponse> handleVerifyEmailForRegistration(
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

              // if everthing is valid, verify the user account
              user.setAccountStatus(User.AccountStatus.ACTIVE);
              user.setUpdatedAt(OffsetDateTime.now());

              return userRepository.save(user);
            })
        .map(
            saveUser -> {

              // TODO: generate access token and refresh token here.
              //              String accessToken = JwtUtils.generateAccessToken()
              String accessToken = "mock-access-token";
              //              String refreshToken = JwtUtils.generateAccessToken()
              String refreshToken = "mock-refresh-token";

              Map<String, String> tokenMap =
                  Map.of(ACCESS_TOKEN_KEY, accessToken, REFRESH_TOKEN_KEY, refreshToken);

              VerifyEmailResponse response = new VerifyEmailResponse();
              response.setType(ACCOUNT_REGISTRATION.toString());
              response.tokens(tokenMap);
              response.setMessage("Email verified successfully!");

              return response;
            });
  }

  private Mono<VerifyEmailResponse> handleVerifyEmailForForgotPassword(
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

              // TODO: you need to save the resetPasswordToken here with the user info
              // it should be a JWE
              String resetPasswordToken = "asdbadqwe";
              return Mono.just(resetPasswordToken);
            })
        .map(
            resetPasswordToken -> {
              Map<String, String> tokenMap = Map.of(RESET_PASSWORD_TOKEN_KEY, resetPasswordToken);

              VerifyEmailResponse response = new VerifyEmailResponse();
              response.setType(FORGOT_PASSWORD.toString());
              response.tokens(tokenMap);
              response.setMessage("Email verified successfully!");
              return response;
            });
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

  private ErrorCode validateResendEmailRequest(User user, String emailVerificationType) {
    // check if the request type for sending email is valid
    boolean isValidRequestType =
        Objects.nonNull(emailVerificationType)
            && Arrays.stream(values())
                .anyMatch(type -> type.name().equals(emailVerificationType.toUpperCase()));
    if (!isValidRequestType) {
      return ErrorCode.AUTH_ERROR8;
    }

    VerificationCode.Type requestType = VerificationCode.Type.valueOf(emailVerificationType);
    // user can only request resending email for account registration only when the account is
    // unverified
    if (requestType.equals(ACCOUNT_REGISTRATION)
        && !Objects.equals(User.AccountStatus.UNVERIFIED, user.getAccountStatus())) {
      return ErrorCode.AUTH_ERROR9;
    }

    return null;
  }

  private String generateVerificationCode() {
    // Implement a method to generate a random verification code
    return UUID.randomUUID().toString().substring(0, 6).toUpperCase();
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
