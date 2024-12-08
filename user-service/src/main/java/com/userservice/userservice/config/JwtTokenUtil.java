package com.userservice.userservice.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtTokenUtil {

    private static final String SECRET = "MY_SUPER_SECURE_SECRET_KEY_WITH_AT_LEAST_256_BITS";
    private final Key SECRET_KEY = new SecretKeySpec(
            Base64.getEncoder().encode(SECRET.getBytes()),
            SignatureAlgorithm.HS256.getJcaName()
    );

    // Validera token
    public Claims validateToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // Generera token för användare
    public String generateToken(String username, String role) {
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(SECRET_KEY)
                .compact();
    }

    // Generera token för inter-service kommunikation
    public String generateInternalToken() {
        return Jwts.builder()
                .setSubject("user-service")
                .claim("role", "ROLE_INTERNAL")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(SECRET_KEY)
                .compact();
    }
}
