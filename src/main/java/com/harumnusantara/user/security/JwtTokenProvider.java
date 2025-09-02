package com.harumnusantara.user.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
@Slf4j
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    @Getter
    private String jwtSecret;

    @Value("${jwt.expiration}")
    @Getter
    private long jwtExpiration;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    public String generateToken(Authentication authentication) {
        // getting user details from the authentication object
        UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();

        // setting roles to token
        List<String> roles = userPrincipal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        // set a token expiration time
        Date expiryDate = new Date(System.currentTimeMillis() + jwtExpiration);

        // creating a JWT token with jjwt library
        String token = Jwts.builder()
                .subject(userPrincipal.getUsername())
                .claim("roles", roles)
                .issuedAt(new Date())
                .expiration(expiryDate)
                .signWith(getSigningKey(), Jwts.SIG.HS512)
                .compact();

        log.debug("Generated JWT Token for User: {}", userPrincipal.getUsername());
        return token;
    }

    public String generateTokenFromUsername(String username) {
        List<String> roles = List.of("ROLE_USER");
        Date expiryDate = new Date(System.currentTimeMillis() + jwtExpiration);
        return Jwts.builder()
                .subject(username)
                .claim("roles", roles)
                .issuedAt(new Date())
                .expiration(expiryDate)
                .signWith(getSigningKey(), Jwts.SIG.HS512)
                .compact();
    }

    public String getUsernameFromToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return claims.getSubject();
        } catch (Exception ex) {
            log.error("Error parsing token: ", ex);
            throw ex;
        }
    }

    public Date getExpirationDateFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims.getExpiration();
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(authToken);

            log.debug("JWT token is valid");
            return true;
        } catch (MalformedJwtException ex) {
            log.error("Invalid JWT token: {}", ex.getMessage());
        } catch (ExpiredJwtException ex) {
            log.error("Expired JWT token: {}", ex.getMessage());
        } catch (UnsupportedJwtException ex) {
            log.error("Unsupported JWT token: {}", ex.getMessage());
        } catch (IllegalArgumentException ex) {
            log.error("JWT claims string is empty: {}", ex.getMessage());
        } catch (Exception ex) {
            log.error("JWT token validation error: {}", ex.getMessage());
        }
        return false;
    }

    public boolean isTokenExpired(String token) {
        try {
            Date expiration = getExpirationDateFromToken(token);
            return expiration.before(new Date());
        } catch (Exception ex) {
            log.error("Error checking token expiration: {}", ex.getMessage());
            return true;
        }
    }

    public long getRemainingTimeInMs(String token) {
        try {
            Date expiration = getExpirationDateFromToken(token);
            long remainingTime = expiration.getTime() - System.currentTimeMillis();
            return Math.max(remainingTime, 0);
        } catch (Exception ex) {
            log.error("Error getting remaining time: {}", ex.getMessage());
            return 0;
        }
    }

    public List<String> getRolesFromToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            List<String> roles = claims.get("roles", List.class);
            return roles != null ? roles : new ArrayList<>();
        } catch (Exception e) {
            log.error("Error getting roles from token: ", e);
            return new ArrayList<>();
        }
    }

}
