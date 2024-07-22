package com.chat.auth_service.utils;

import com.chat.auth_service.entity.LoginHistory;
import com.chat.auth_service.entity.User;
import com.chat.auth_service.exception.ApplicationException;
import com.chat.auth_service.exception.ErrorCode;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtUtils {
  @Value("${jwt.secret-key}")
  private String SECRET_KEY;

  @Value("${jwt.expiration-time-access-token}")
  private String EXPIRATION_TIME_ACCESS_TOKEN;

  @Value("${jwt.expiration-time-refresh-token}")
  private String EXPIRATION_TIME_REFRESH_TOKEN;

  private final String USER_AGENT = "USER_AGENT";
  private final String IP_ADDRESS = "IP_ADDRESS";

  public String generateAccessToken(User user) {

    Map<String, String> claims =
        Map.of(
            "user_id",
            Utils.convertUUIDToString(user.getId()),
            "user_agent",
            USER_AGENT,
            "ip_address",
            IP_ADDRESS);
    return Jwts.builder()
        .claims(claims)
        .subject(user.getEmail())
        .issuedAt(new Date())
        .expiration(
            new Date(
                System.currentTimeMillis()
                    + Long.parseLong(EXPIRATION_TIME_ACCESS_TOKEN) * 60 * 1000))
        .signWith(getSigningKey(), SignatureAlgorithm.HS256)
        .compact();
  }

  public String generateRefreshToken(User user) {
    Map<String, String> claims =
        Map.of(
            "user_id",
            Utils.convertUUIDToString(user.getId()),
            "user_agent",
            USER_AGENT,
            "ip_address",
            IP_ADDRESS);
    return Jwts.builder()
        .claims(claims)
        .subject(user.getEmail())
        .issuedAt(new Date())
        .expiration(
            new Date(
                System.currentTimeMillis()
                    + Long.parseLong(EXPIRATION_TIME_REFRESH_TOKEN) * 60 * 60 * 1000))
        .signWith(getSigningKey(), SignatureAlgorithm.HS256)
        .compact();
  }

  public String generateResetPasswordToken(User user) {
    Map<String, String> claims =
        Map.of(
            "user_id",
            Utils.convertUUIDToString(user.getId()),
            "user_agent",
            USER_AGENT,
            "ip_address",
            IP_ADDRESS);
    return Jwts.builder()
        .claims(claims)
        .subject(user.getEmail())
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + 30 * 60 * 1000))
        // TODO: this should be JWE

        .signWith(getSigningKey())
        .compact();
  }

  private SecretKey getSigningKey() {
    byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
    return Keys.hmacShaKeyFor(keyBytes);
  }

  public String extractUserID(String jwt) {
    return extractClaim(jwt, claims -> claims.get("user_id", String.class));
  }

  public String extractUserAgent(String jwt) {
    return extractClaim(jwt, claims -> claims.get("user_agent", String.class));
  }

  public String extractIpAddress(String jwt) {
    return extractClaim(jwt, claims -> claims.get("ip_address", String.class));
  }

  private <T> T extractClaim(String jwt, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(jwt);
    return claimsResolver.apply(claims);
  }

  private Claims extractAllClaims(String jwt) {
    try {
      return Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(jwt).getPayload();
    } catch (Exception e) {
      throw new ApplicationException(ErrorCode.AUTH_ERROR14);
    }
  }

  public String extractUserEmail(String jwt) {
    return extractAllClaims(jwt).getSubject();
  }

  public boolean validateAccessToken(String jwt, LoginHistory loginHistory, User user) {
    final String userID = extractUserID(jwt);
    final String userAgent = extractUserAgent(jwt);
    final String ipAddress = extractIpAddress(jwt);
    final String email = extractClaim(jwt, Claims::getSubject);

    if (!loginHistory.getUserId().toString().equals(userID)
        || !loginHistory.getUserAgent().equals(userAgent)
        || !loginHistory.getIpAddress().equals(ipAddress)
        || !user.getEmail().equals(email)) {
      throw new ApplicationException(ErrorCode.AUTH_ERROR14);
    } else if (isTokenExpired(jwt)) {
      throw new ApplicationException(ErrorCode.AUTH_ERROR15);
    }
    return true;
  }

  public boolean validateRefreshToken(String jwt) {
    final String userID = extractUserID(jwt);
    final String userAgent = extractUserAgent(jwt);
    final String ipAddress = extractIpAddress(jwt);

    // TODO: get the userId and userAgent in the header

    //    if (!loginHistory.getUserId().toString().equals(userID)
    //        || !loginHistory.getUserAgent().equals(userAgent)
    //        || !loginHistory.getIpAddress().equals(ipAddress)) {
    //      throw new ApplicationException(ErrorCode.AUTH_ERROR14);
    //    } else if (isTokenExpired(jwt)) {
    //      throw new ApplicationException(ErrorCode.AUTH_ERROR15);
    //    }
    return true;
  }

  public boolean isTokenExpired(String jwt) {
    return extractExpiration(jwt).before(new Date());
  }

  private Date extractExpiration(String jwt) {
    return extractClaim(jwt, Claims::getExpiration);
  }
}
