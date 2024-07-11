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

public class JwtUtils {
    private static final String SECRET_KEY = "462D4A614E645267556B58703272357538782F413F4428472B4B625065536856";

    public static String generateToken(User user, LoginHistory loginHistory) {

        Map<String, String> claims = Map.of("user_id", user.getId(),
                "user_agent", loginHistory.getUserAgent(),
                "ip_address", loginHistory.getIpAddress());

        return Jwts
                .builder()
                .setSubject(user.getEmail())
                .setClaims(claims)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 365)) // 1 year
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private static Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
