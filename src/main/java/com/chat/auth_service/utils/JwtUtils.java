package com.chat.auth_service.utils;

import com.chat.auth_service.entity.LoginHistory;
import com.chat.auth_service.entity.User;
import com.chat.auth_service.exception.ApplicationException;
import com.chat.auth_service.exception.ErrorCode;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;

public class JwtUtils {
  @Value("${jwt.secret-key}")
  private static String SECRET_KEY;

  @Value("${jwt.expiration-time-access-token}")
  private static Long EXPIRATION_TIME_ACCESS_TOKEN;

  @Value("${jwt.expiration-time-refresh-token}")
  private static Long EXPIRATION_TIME_REFRESH_TOKEN;

  public static String generateAccessToken(User user, LoginHistory loginHistory) {

    Map<String, String> claims =
        Map.of(
            "user_id",
            Utils.convertUUIDToString(user.getId()),
            "user_agent",
            loginHistory.getUserAgent(),
            "ip_address",
            loginHistory.getIpAddress());
    return Jwts.builder()
        .claims(claims)
        .subject(user.getEmail())
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME_ACCESS_TOKEN * 60 * 1000))
        .signWith(getSigningKey(), Jwts.SIG.NONE)
        .compact();
  }

  public static String generateRefreshToken(User user, LoginHistory loginHistory) {
    Map<String, String> claims =
        Map.of(
            "user_id",
            Utils.convertUUIDToString(user.getId()),
            "user_agent",
            loginHistory.getUserAgent(),
            "ip_address",
            loginHistory.getIpAddress());
    return Jwts.builder()
        .claims(claims)
        .issuedAt(new Date())
        .expiration(
            new Date(System.currentTimeMillis() + EXPIRATION_TIME_REFRESH_TOKEN * 60 * 60 * 1000))
        .signWith(getSigningKey(), Jwts.SIG.NONE)
        .compact();
  }

  public static String extractUserID(String jwt) {
    return extractClaim(jwt, claims -> claims.get("user_id", String.class));
  }

  public static String extractUserAgent(String jwt) {
    return extractClaim(jwt, claims -> claims.get("user_agent", String.class));
  }

  public static String extractIpAddress(String jwt) {
    return extractClaim(jwt, claims -> claims.get("ip_address", String.class));
  }

  private static <T> T extractClaim(String jwt, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(jwt);
    return claimsResolver.apply(claims);
  }

  private static Claims extractAllClaims(String jwt) {
    try {
      return Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(jwt).getPayload();
    } catch (Exception e) {
      throw new ApplicationException(ErrorCode.AUTH_ERROR14);
    }
  }

  private static SecretKey getSigningKey() {
    byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
    return Keys.hmacShaKeyFor(keyBytes);
  }

  public static boolean validateAccessToken(String jwt, LoginHistory loginHistory, User user) {
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

  public static boolean validateRefreshToken(String jwt, LoginHistory loginHistory) {
    final String userID = extractUserID(jwt);
    final String userAgent = extractUserAgent(jwt);
    final String ipAddress = extractIpAddress(jwt);

    if (!loginHistory.getUserId().toString().equals(userID)
        || !loginHistory.getUserAgent().equals(userAgent)
        || !loginHistory.getIpAddress().equals(ipAddress)) {
      throw new ApplicationException(ErrorCode.AUTH_ERROR14);
    } else if (isTokenExpired(jwt)) {
      throw new ApplicationException(ErrorCode.AUTH_ERROR15);
    }
    return true;
  }

  private static boolean isTokenExpired(String jwt) {
    return extractExpiration(jwt).before(new Date());
  }

  private static Date extractExpiration(String jwt) {
    return extractClaim(jwt, Claims::getExpiration);
  }
}
