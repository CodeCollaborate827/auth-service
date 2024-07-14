package com.chat.auth_service.service.implementation;

import com.chat.auth_service.entity.*;
import com.chat.auth_service.exception.ApplicationException;
import com.chat.auth_service.exception.ErrorCode;
import com.chat.auth_service.repository.*;
import com.chat.auth_service.server.model.*;
import com.chat.auth_service.service.AuthService;
import com.chat.auth_service.utils.JwtUtils;
import com.chat.auth_service.utils.MailUtils;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static com.chat.auth_service.entity.VerificationCode.Type.*;

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

  @Override
  public Mono<ResponseEntity<Login200Response>> login(Mono<LoginRequest> loginRequest) {
    return loginRequest.flatMap(
            request ->
                    Mono.zip(
                                    userRepository.findByEmail(request.getEmail()),
                                    authenticationSettingRepository.findByUserId(
                                            null)) // TODO: we need to discuss this
                            .flatMap(
                                    tuple -> {
                                      User user = tuple.getT1();
                                      AuthenticationSetting authSettings = tuple.getT2();

                                      // Check if user exists
                                      Mono.just(user)
                                              .switchIfEmpty(
                                                      Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR1)));

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

                                      // find all login history for the user and check ip_address and user_agent is
                                      // matching or not
                                      return loginHistoryRepository
                                              .findAllByUserId(user.getId())
                                              .collectList()
                                              .flatMap(
                                                      loginHistories -> {
                                                        LoginHistory loginHistory =
                                                                loginHistories.stream()
                                                                        .filter(
                                                                                history ->
                                                                                        history
                                                                                                .getIpAddress()
                                                                                                .equals(request.getIpAddress())
                                                                                                && history
                                                                                                .getUserAgent()
                                                                                                .equals(request.getUserAgent()))
                                                                        .findFirst()
                                                                        .orElse(null);

                                                        if (loginHistory == null) {
                                                          loginHistory = new LoginHistory();
                                                          loginHistory.setUserId(user.getId());
                                                          loginHistory.setIpAddress(request.getIpAddress());
                                                          loginHistory.setUserAgent(request.getUserAgent());
                                                        }

                                                        if (!loginHistory.getIsSaved()) {
                                                          // Check if MFA is required
                                                          if (authSettings.getMfaEnabled()) {
                                                            return handleMfaLogin(user, request);
                                                          }
                                                        }

                                                        // save login history
                                                        if (!loginHistory.getIsSuccessful())
                                                          loginHistory.setIsSuccessful(true);
                                                        loginHistoryRepository.save(loginHistory).then(Mono.just(user));

                                                        // Generate and save refresh token
                                                        String accessToken =
                                                                JwtUtils.generateAccessToken(user, loginHistory);
                                                        return saveRefreshToken(user, loginHistory)
                                                                .map(
                                                                        refreshToken ->
                                                                                ResponseEntity.ok(
                                                                                        new Login200Response()
                                                                                                .refreshToken(refreshToken.getRefreshToken())
                                                                                                .accessToken(accessToken)));
                                                      });
                                    }));
  }

  @Override
  public Mono<ResponseEntity<Register200Response>> register(Mono<RegisterRequest> registerRequest) {
    return registerRequest.flatMap(
            request -> {
              // Check if email is already registered
              return userRepository
                      .findByEmail(request.getEmail())
                      .flatMap(existingUser -> Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR6)))
                      .then(Mono.defer(() -> userRepository.findByUsername(request.getUsername())))
                      .flatMap(
                              existingUser ->
                                      Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR4))
                                              .then(
                                                      Mono.defer(
                                                              () -> {
                                                                // Create user
                                                                User newUser = new User();
                                                                newUser.setEmail(request.getEmail());
                                                                newUser.setUsername(request.getUsername());
                                                                newUser.setPasswordHash(
                                                                        passwordEncoder.encode(request.getPassword()));
                                                                newUser.setAccountType(User.AccountType.NORMAL);
                                                                newUser.setAccountStatus(
                                                                        User.AccountStatus
                                                                                .UNVERIFIED); // Set to INACTIVE until email is verified

                                                                // Create authentication setting
                                                                AuthenticationSetting authSetting = new AuthenticationSetting();
                                                                authSetting.setUserId(newUser.getId());
                                                                authSetting.setMfaEnabled(
                                                                        false); // Default to false, can be enabled later

                                                                // Generate email verification code
                                                                VerificationCode verificationCode = new VerificationCode();
                                                                verificationCode.setUserId(newUser.getId());
                                                                verificationCode.setType(
                                                                        ACCOUNT_REGISTRATION);
                                                                verificationCode.setCode(
                                                                        generateVerificationCode()); // Implement this method
                                                                verificationCode.setExpiration(
                                                                        OffsetDateTime.now().plusHours(24)); // 24 hours validity

                                                                return Mono.zip(
                                                                                userRepository.save(newUser),
                                                                                authenticationSettingRepository.save(authSetting),
                                                                                verificationCodeRepository.save(verificationCode))
                                                                        .flatMap(
                                                                                tuple -> {
                                                                                  User savedUser = tuple.getT1();
                                                                                  VerificationCode savedCode = tuple.getT3();
                                                                                  // Send verification email
                                                                                  return Mono.fromFuture(
                                                                                                  () ->
                                                                                                          mailUtils.sendVerificationEmail(
                                                                                                                  "Verify email", savedUser.getEmail(), savedCode))
                                                                                          .then(Mono.just(savedUser));
                                                                                });
                                                              }))
                                              .map(
                                                      savedUser -> {
                                                        Register200Response response = new Register200Response();
                                                        response.setMessage(
                                                                "Registration successful. Please check your email to verify your account.");
                                                        return ResponseEntity.ok(response);
                                                      }));
            });
  }

  @Override
  public Mono<ResponseEntity<CommonResponse>> rendSendVerificationEmail(
          Mono<ResendVerificationEmailRequest> resendVerificationEmailRequest) {

    //TODO: some of the logic is the same as sending verification email;

    return resendVerificationEmailRequest.flatMap(request -> {
      return userRepository.findByEmail(request.getEmail())
              // check if user exists
              .switchIfEmpty(Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR1)))
              // validate the request
              .flatMap(user -> {
                ErrorCode errorCode = validateResendEmailRequest(user, request.getType());
                if (errorCode != null) {
                  return Mono.error(new ApplicationException(errorCode));
                }

                return Mono.just(user);
              })
              // check the rate limit of resending the request
              .flatMap(user -> {
                return verificationCodeRepository.findByUserIdAndTypeLatest(user.getId(), VerificationCode.Type.valueOf(request.getType()))
                        .flatMap(verificationCode -> {
                          boolean exceededRateLimit = checkExceedRateLimit(verificationCode);
                          if (exceededRateLimit) {
                            return Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR8));
                          }

                          return Mono.just(user);
                        })
                        // if not verification exist, then continue processing
                        .switchIfEmpty(Mono.just(user));
              })
              // create new verification code and save it
              .flatMap(user -> {
                VerificationCode verificationCode = new VerificationCode();
                verificationCode.setType(VerificationCode.Type.valueOf(request.getType()));
                verificationCode.setExpiration(OffsetDateTime.now().plusMinutes(30)); // TODO: this should be in application.properties
                verificationCode.setUserId(user.getId());
                verificationCode.setCode(generateVerificationCode());

                return verificationCodeRepository.save(verificationCode);
              })
              .map(verificationCode -> {

                // email is sent asynchronously
                mailUtils.sendVerificationEmail("EMAIL VERIFICATION", request.getEmail(), verificationCode);

                CommonResponse response = new CommonResponse();
                response.setMessage("Email is being sent successfully");
                return ResponseEntity.ok(response);
              });

    });
  }

  private boolean checkExceedRateLimit(VerificationCode verificationCode) {
//    verificationCode.get
    OffsetDateTime now = OffsetDateTime.now();
    Duration between = Duration.between(now, verificationCode.getCreatedAt());
    return !now.isAfter(verificationCode.getCreatedAt()) || between.toSeconds() < 120; // TODO: this 120 value should be in application.properties
  }

  private ErrorCode validateResendEmailRequest(User user, String emailVerificationType) {
    // check if the request type for sending email is valid
    boolean isValidRequestType = Objects.isNull(emailVerificationType) || Arrays.stream(
            values()).anyMatch(type -> type.name()
            .equals(emailVerificationType.toUpperCase()));
    if (isValidRequestType) {
      return ErrorCode.AUTH_ERROR8;

    }

    // user can only request resending email for account registration only when the account is unverified
    if (!Objects.equals(User.AccountStatus.UNVERIFIED, user.getAccountStatus())) {
      return ErrorCode.AUTH_ERROR9;
    }

    return null;
  }

  private String generateVerificationCode() {
    // Implement a method to generate a random verification code
    return UUID.randomUUID().toString().substring(0, 6).toUpperCase();
  }

  private Mono<RefreshToken> saveRefreshToken(User user, LoginHistory loginHistory) {
    RefreshToken refreshToken = new RefreshToken();
    refreshToken.setLoginId(loginHistory.getId());
    refreshToken.setRefreshToken(JwtUtils.generateRefreshToken(user, loginHistory));
    refreshToken.setUsageCount(1);
    refreshToken.setLimitUsageCount(5);

    return refreshTokenRepository.save(refreshToken);
  }

  private Mono<Void> saveFailedLoginHistory(UUID userId, LoginRequest loginRequest) {
    LoginHistory failedLogin = new LoginHistory();
    failedLogin.setUserId(userId);
    failedLogin.setIpAddress(loginRequest.getIpAddress());
    failedLogin.setUserAgent(loginRequest.getUserAgent());
    failedLogin.setIsSuccessful(false);
    return loginHistoryRepository.save(failedLogin).then();
  }

  private Mono<ResponseEntity<Login200Response>> handleMfaLogin(User user, LoginRequest request) {
    // Implement MFA logic here
    // This could involve generating and sending a verification code,
    // or checking a TOTP code, etc.
    // Return appropriate response or error
    return Mono.error(new ApplicationException(ErrorCode.AUTH_ERROR5));
  }
}
