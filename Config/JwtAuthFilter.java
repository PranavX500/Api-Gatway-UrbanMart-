package com.example.API_Gateway.Config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Component
@Order(-1)
public class JwtAuthFilter implements GlobalFilter {

    @Value("${jwt.secretKey}")
    private String SECRET;

    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
    }

    public JwtAuthFilter() {
        System.out.println("🔥 JWT FILTER LOADED SUCCESSFULLY 🔥");
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        System.out.println("=== JWT FILTER STARTED ===");
        System.out.println("Request Path: " + exchange.getRequest().getURI().getPath());
        System.out.println("Request Method: " + exchange.getRequest().getMethod());

        String path = exchange.getRequest().getURI().getPath();

        // Public endpoints
        if (path.startsWith("/auth/login") ||
                path.startsWith("/auth/signup") ||
                path.startsWith("/OTP/Validate")) {
            System.out.println("⏩ SKIPPING JWT FILTER FOR PUBLIC PATH: " + path);
            return chain.filter(exchange);
        }

        System.out.println("🔐 PROTECTED PATH - REQUIRES JWT VALIDATION");

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        System.out.println("AUTH HEADER RECEIVED → " + authHeader);

        System.out.println("COOKIES RECEIVED → " + exchange.getRequest().getCookies());

        // Log all headers for debugging
        System.out.println("ALL HEADERS:");
        exchange.getRequest().getHeaders().forEach((key, values) -> {
            System.out.println("  " + key + ": " + values);
        });

        String token = null;

        // 1. Check Authorization header first
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            System.out.println("✅ TOKEN EXTRACTED FROM AUTHORIZATION HEADER");
            System.out.println("TOKEN (first 50 chars): " + (token.length() > 50 ? token.substring(0, 50) + "..." : token));
        }

        // 2. If no token in header, check cookies
        if (token == null) {
            System.out.println("🔍 CHECKING COOKIES FOR TOKEN...");
            if (exchange.getRequest().getCookies().containsKey("token")) {
                List<String> cookieValues = exchange.getRequest().getCookies().get("token").stream()
                        .map(cookie -> cookie.getValue())
                        .toList();

                if (!cookieValues.isEmpty()) {
                    String cookieValue = cookieValues.get(0);
                    System.out.println("RAW COOKIE VALUE: \"" + cookieValue + "\"");
                    System.out.println("COOKIE VALUE LENGTH: " + cookieValue.length());

                    // Parse the cookie value - it might be in format "token=JWT_TOKEN"
                    // Let's debug what's in the cookie
                    System.out.println("COOKIE STARTS WITH 'token=': " + cookieValue.startsWith("token="));

                    if (cookieValue.startsWith("token=")) {
                        token = cookieValue.substring(6); // Remove "token=" prefix
                        System.out.println("✅ EXTRACTED TOKEN FROM 'token=' PREFIX");
                    } else if (cookieValue.startsWith("Bearer ")) {
                        token = cookieValue.substring(7); // Remove "Bearer " prefix
                        System.out.println("✅ EXTRACTED TOKEN FROM 'Bearer ' PREFIX");
                    } else {
                        token = cookieValue; // Use as-is if no prefix
                        System.out.println("✅ USING COOKIE VALUE AS-IS");
                    }

                    if (token != null) {
                        System.out.println("✅ TOKEN EXTRACTED FROM COOKIE");
                        System.out.println("TOKEN (first 50 chars): " + (token.length() > 50 ? token.substring(0, 50) + "..." : token));
                    }
                }
            } else {
                System.out.println("❌ NO 'token' COOKIE FOUND");
            }
        }

        if (token == null || token.isEmpty()) {
            System.out.println("❌ NO TOKEN FOUND - Returning 401");
            System.out.println("=== JWT FILTER ENDED (UNAUTHORIZED) ===");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        try {
            System.out.println("🔑 ATTEMPTING TO VALIDATE JWT TOKEN...");

            // ⭐ Correct JJWT parsing
            Claims claims = Jwts.parser()
                    .verifyWith(getSecretKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            String username = claims.getSubject();
            String email = claims.get("email", String.class);
            String role = claims.get("role", String.class);
            Object userIdObj = claims.get("userId");
            String userId = String.valueOf(userIdObj);

            System.out.println("✅ TOKEN VALIDATED SUCCESSFULLY!");
            System.out.println("  👤 Username: " + username);
            System.out.println("  📧 Email: " + email);
            System.out.println("  🎭 Role: " + role);
            System.out.println("  🆔 UserId: " + userId);

            ServerHttpRequest modifiedRequest = exchange.getRequest()
                    .mutate()
                    .header("X-USERNAME", username)
                    .header("X-EMAIL", email)
                    .header("X-ROLES", role)
                    .header("X-UserId", userId)
                    .build();

            System.out.println("✅ HEADERS ADDED TO REQUEST");
            System.out.println("=== JWT FILTER ENDED (SUCCESS) ===");

            return chain.filter(exchange.mutate().request(modifiedRequest).build());

        } catch (Exception e) {
            System.out.println("❌ TOKEN VALIDATION FAILED!");
            System.out.println("Error: " + e.getClass().getName() + " - " + e.getMessage());
            System.out.println("Token being validated: " + token);
            e.printStackTrace();
            System.out.println("=== JWT FILTER ENDED (VALIDATION FAILED) ===");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }
}