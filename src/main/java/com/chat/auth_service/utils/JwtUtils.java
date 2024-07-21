package com.chat.auth_service.utils;

import com.chat.auth_service.entity.LoginHistory;
import com.chat.auth_service.entity.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.Map;
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

  public String generateAccessToken(User user, LoginHistory loginHistory) {

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
        .expiration(new Date(System.currentTimeMillis() + Long.parseLong(EXPIRATION_TIME_ACCESS_TOKEN) * 60 * 1000))
        .signWith(getSigningKey(), SignatureAlgorithm.HS256)
        .compact();
  }

  public String generateRefreshToken(User user, LoginHistory loginHistory) {
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
        .expiration(
            new Date(System.currentTimeMillis() + Long.parseLong(EXPIRATION_TIME_REFRESH_TOKEN) * 60 * 60 * 1000))
        .signWith(getSigningKey(), SignatureAlgorithm.HS256)
        .compact();
  }

  private Key getSigningKey() {
    byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
    return Keys.hmacShaKeyFor(keyBytes);
  }
}
